# frozen_string_literal: true

require_relative 'factorio_wire'

# The Factorio SAVE format's reader: its string container (FactorioWire, with
# the save's NUL-terminated framing) and the player-record fields we read out
# of a save (docs/save/level-dat.md has the byte-level notes and the
# measurements behind every constant here).
#
# The save's own table/value encoding is NOT decoded here: what a save stores
# for a player is read field by field (the scanner below), and the value
# container that Factorio uses for mod settings in a PACKET is a different,
# documented format — see FactorioPropertyTree.
#
# Every string in the save is length-prefixed and NUL terminated — ONE
# container, in every place we have found one. Seen in the wild as:
#
#   [len][name] 00        player name (followed by 00 00: the NUL, then a field)
#   01 00 [len][loc] 00   the player's locale
#   [len][tag] [len][tag] a chain: the 2.0 player tags
#   01 [len][key]         a table key (mod storage, GUI strings)
module FactorioSave
  extend FactorioWire # the shared string/varint reader (lib/factorio_wire.rb)

  # The save's string: the shared reader with the save's framing — the NUL
  # terminator is REQUIRED (a missing one is a bad decode, not a field), and
  # `nul: false` reads the packet protocol's unterminated variant.
  def self.string_at(data, at, nul: true)
    FactorioWire.string_at(data, at, terminator: nul ? 0 : nil) # explicit: we override the inherited name
  end

  # A run of strings (tags, mod names): -> [[String, ...], offset_after].
  # Stops at the first byte that cannot start one — and PRINTABLE only: binary
  # junk that happens to look like a 1-byte string (`01 00` is a table marker,
  # not the tag "\x01") must not be walked into. An empty run is not a run.
  PRINTABLE = /\A[[:print:]]+\z/
  def self.string_chain(data, at, limit: 64, nul: true)
    out = []
    while out.size < limit
      found = string_at(data, at, nul: nul)
      break unless found && found[0].match?(PRINTABLE)
      out << found[0]
      at = found[1]
    end
    [out, at]
  end

  def self.force_utf8(bytes)
    bytes.dup.force_encoding(Encoding::UTF_8).scrub('?')
  end
  def self.u32(data, at)
    data.byteslice(at, 4)&.unpack1('V')
  end

  def self.u64(data, at)
    data.byteslice(at, 8)&.unpack1('Q<')
  end

  # ── Player records ────────────────────────────────────────────────
  #
  # A record is found by its NAME field, which is a bare optim-string right
  # after a block of floats whose last one is 1.0f — so the name is always
  # preceded by the bytes 00 80 3f (that float's tail). A 24-bit signature
  # over a ~186 MB stream; outside the roster it only matches item / planet /
  # recipe prototype names, and never a player name (Factorio rejects spaces
  # and other punctuation in names, so the charset below is a real filter).
  NAME_MAX = 32
  NAME_RE = /\x00\x80\x3f([\x03-\x20])([A-Za-z0-9_.\-]{3,32})/n
  # The locale field: 01 00, the string, then 00 00 00 00 ff ff ff. Unique
  # inside a record (290 of 338 records carry it, ZERO wrong values).
  LOCALE_RE = /\x01\x00([\x02-\x08])([a-z]{2}(?:-[A-Za-z]{2,4})?)\x00\x00\x00\x00\xff\xff\xff/n

  # How far behind the name the locale may sit (it can be deep in a record's
  # variable tail; measured quartiles 96 / 1.5 KB / 4.7 KB, max 1.5 MB).
  LOCALE_WINDOW = 65_536
  # How far in front of the name the play-time / last-online u64 pair sits.
  STAT_WINDOW = 140

  # One record as found in the stream. `pairs`/`locales` are raw candidates
  # (offsets + values); #roster picks between them.
  Record = Struct.new(:pos, :name, :offset, :pairs, :locale_candidates, keyword_init: true)

  # Every `[u32 play][0][u32 last][0]` pair in front of the name at `at`.
  # Both are u64-sized slots holding a u32 value; play < last.
  def self.stat_pairs(data, at)
    pairs = []
    ([at - STAT_WINDOW, 0].max...(at - 4)).each do |p|
      next if p + 16 > data.bytesize
      next unless u32(data, p + 4).zero? && u32(data, p + 12).zero?
      play = u32(data, p)
      last = u32(data, p + 8)
      pairs << [p - at, play, last] if play.positive? && play < last
    end
    pairs
  end

  # The player's TAGS (2.0), the string chain right after the name. nil when
  # there are none — which is the common case.
  def self.tags_at(data, at)
    strings, = string_chain(data, at)
    strings.empty? ? nil : strings
  end

  # LuaPlayer.color: four f32 floats just in front of the name — measured
  # against a live game.players dump, 337 of 338 records give the exact four
  # floats here. `color` in players-cache.json is the same value, rounded the
  # way RconClient.parse_color rounds it.
  #
  # The channels are ordinary floats, so a plausible-looking quadruple is NOT
  # proof on its own: one record in 338 sits at this offset in a layout that is
  # not the colour, and it lands on another player's real grey — there is no
  # local tell. 337/338 exact, and the tool says so.
  #
  # Measured on our save: 39 distinct colours over 338 players (22 of them
  # held by 14-44 players each, 17 by a single player — the game's colour
  # picker offers a set of swatches and most players stay on one, a few set
  # their own), and alpha is 0.5 for every single player: nobody has ever
  # touched it, so it is the default and not evidence of anything.
  COLOR_OFFSET = -33
  def self.color_at(data, name_at)
    off = name_at + COLOR_OFFSET
    return nil if off < 0 || off + 16 > data.bytesize
    rgba = (0...4).map { |i| data.byteslice(off + (i * 4), 4).unpack1('f') }
    return nil unless rgba.all? { |v| v.is_a?(Numeric) && v >= 0.0 && v <= 1.0 }
    rgba.map { |v| v.round(4) }
  end

  # ── Scanning a save for the player records ───────────────────────
  #
  # Streams the decompressed level.dat (memory-light: one carry buffer) and
  # returns every player record it finds, in file order, with the play-time /
  # last-online pair and the locale resolved. The ROSTER (the run of records)
  # is picked out of these by the caller, which knows the game indexes — or,
  # for a save whose players have never been seen, by "has a stat pair".
  class Roster
    # Bytes kept between buffers so a name cannot straddle a chunk edge and
    # both field windows are complete.
    CARRY = LOCALE_WINDOW + STAT_WINDOW + 64

    # stream: an Enumerable of byte chunks (see each_chunk in the tool).
    def initialize(stream)
      @records = scan(stream)
    end

    # => [{name:, online_time_ticks:, last_online_tick:, locale:, color:, slot:}, …]
    attr_reader :records
    # The two offsets in front of the name the stat pair really sits at (a
    # save has a couple of record layouts — -57 and -63 in ours), and the
    # save's own tick (the largest last-online seen in the top slot).
    attr_reader :slots, :save_tick

    private

    def scan(stream)
      candidates = []
      buf = String.new(encoding: Encoding::BINARY)
      base = 0 # absolute offset of buf[0] in the stream
      last = -1 # a carried-over name can match twice
      stream.each do |chunk|
        buf << chunk.b
        buf.scan(NAME_RE) do
          m = Regexp.last_match
          abs = base + m.begin(0)
          next if abs <= last
          # A name cut off at the buffer edge matches short, fails the length
          # check, and must NOT consume the offset — the next round sees the
          # whole name (which is why CARRY exists).
          next unless m[1].ord == m[2].bytesize
          last = abs
          at = m.begin(0) # the 00 80 3f anchor, 4 bytes before the name
          window = buf.byteslice(at, LOCALE_WINDOW).to_s
          candidates << {
            name: m[2],
            offset: base + at + 4,
            color: FactorioSave.color_at(buf, at + 4),
            pairs: FactorioSave.stat_pairs(buf, at),
            locales: window.enum_for(:scan, LOCALE_RE)
                        .map { [base + at + Regexp.last_match.begin(0), Regexp.last_match[2]] }
          }
        end
        drop = [buf.bytesize - CARRY, 0].max
        base += drop
        buf = buf.byteslice(drop, buf.bytesize - drop)
      end
      resolve(candidates)
    end

    # A locale match belongs to the record it falls inside — the next
    # record's name is the boundary (the search window reaches into it).
    def resolve(candidates)
      @slots = stat_slots(candidates)
      @save_tick = candidates.flat_map { |c| c[:pairs] }
                           .select { |(rel, _, _)| rel == @slots.first }
                           .map { |(_, _, last)| last }.max
      candidates.each_with_index.map do |c, i|
        stop = candidates[i + 1]&.fetch(:offset) || Float::INFINITY
        _, play, last_online = pick_pairs(c[:pairs])
        {
          name: c[:name],
          online_time_ticks: play,
          last_online_tick: last_online,
          locale: c[:locales].find { |(off, _)| off >= c[:offset] && off < stop }&.last,
          color: c[:color],
          slot: @slots
        }
      end
    end

    # Which offsets in front of the name the stat pairs really sit at: the
    # two most common. A byte-shifted decoy pair (which a play time under
    # 2^24 ticks can form out of the value's own zero padding) is always a
    # one-off or inflates every value by 256, so a count tie goes to the slot
    # with the SMALLEST play time. Same "anchor on what almost everything
    # agrees on" trick as the roster's index shift.
    def stat_slots(candidates)
      tally = Hash.new { |h, k| h[k] = [0, nil] } # offset -> [count, smallest play]
      candidates.each { |c| c[:pairs].each { |(rel, play, _)| e = tally[rel]; e[0] += 1; e[1] = play if e[1].nil? || play < e[1] } }
      tally.sort_by { |_, (count, smallest)| [-count, smallest] }.first(2).map(&:first)
    end

    def pick_pairs(pairs)
      slots = pairs.select { |(rel, _, _)| @slots.include?(rel) }
      slots = pairs if slots.empty? # unusual layout: fall back to all of them
      slots = slots.select { |(_, _, last)| last <= @save_tick } if @save_tick
      slots.max_by { |(_, _, last)| last } || [nil, nil, nil]
    end
  end
end
