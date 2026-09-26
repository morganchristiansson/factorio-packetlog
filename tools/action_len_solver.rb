# frozen_string_literal: true

# Length solver for client→server input actions — the shared core of
# tools/measure_action_lens.rb, kept separate so it can be TESTED.
#
# A tick closure's action bytes end at a known offset (the 8-byte [tick][pad]
# trailer), so with every action's length known except one, that one is
# arithmetic: the leftover between its data start and the end of the area, minus
# whatever the actions after it occupy.
#
# Two details are load-bearing, and both were wrong in an earlier version:
#
#   * the walk is SEQUENTIAL and skips each action's payload. Reading every
#     action's header without skipping payloads takes the second "type" from
#     inside the first action's data ([88, 4] instead of [88, 252]) and the
#     arithmetic is then meaningless while looking perfectly fine.
#   * a length is only accepted when the REST of the closure parses to exactly
#     the area end, and at least one action after it has non-zero length — a
#     0-length `nothing` tail aligns any guess. A closure that admits more than
#     one candidate says nothing about any of them.
module ActionLenSolver
  # Actions whose length the PARSER computes from their layout rather than
  # reading it from the table (see HeartbeatPacket#parse_action). The 2.0 table
  # claims 0 for build_terrain, which is exactly the kind of wrong zero this
  # whole exercise exists to eliminate — so their walk length comes from the
  # parser, per payload, and never from the table.
  CODE_PARSED = [171, 240, 294].freeze

  module_function

  # The lengths to walk THIS payload with: the corpus-wide measured map, plus the
  # table's 0-length entries (that is how a `nothing` is stepped over), plus the
  # parser's own lengths for the content-defined actions.
  def walk_lens_for(data, lens, exclude = nil)
    walk = lens.dup
    walk.delete(exclude) if exclude
    FactorioProtocol::ACTIONS_20.each do |t, (_n, len)|
      next unless len == 0 && !CODE_PARSED.include?(t)
      next if t == exclude
      walk[t] = len
    end
    walk.merge(parsed_lengths(data, CODE_PARSED))
  end

  # uint16v: 1 byte, or 0xFF + u16. (0xFF is also the literal 255 — see
  # HeartbeatPacket#parse_action.)
  def u16v(data, off)
    v = data.getbyte(off)
    return nil if v.nil? || (v == 0xFF && off + 2 >= data.bytesize)
    v == 0xFF ? [3, data.unpack1('v', offset: off + 1)] : [1, v]
  end

  # → [action_count, area_start, area_end, data] for a tick closure that can be
  # attributed at all. No lengths are needed for this, which is what lets the
  # measurement cross the hole it is looking for.
  #
  # Rejected: anything that is not a client→server heartbeat (msg 6), closures
  # carrying action segments, more than one tick closure, a 0xFF-escaped count
  # byte, and packets whose last 8 bytes are not a [tick][pad] trailer (its tick
  # within a second of the closure's own).
  def bounds(data)
    # Client→server only. A full capture holds the server's S→C broadcasts too,
    # and those have no [tick][pad] trailer — but relying on the trailer check
    # alone to reject them would be luck, not a filter.
    return nil unless (data.getbyte(0).to_i & 0x1F) == 6
    res = (FactorioProtocol.parse_udp_payload(data) rescue nil)
    hb = res&.dig(:heartbeat)
    return nil unless hb
    tcs = hb[:tick_closures].to_a
    return nil unless tcs.size == 1
    tc = tcs.first
    return nil if (tc[:actions] || []).any? { |a| a[:total_segs] }
    tail = data[-8..]
    return nil unless tail && tail.unpack1('V', offset: 4).zero?
    return nil unless (tail.unpack1('V') - tc[:tick]).abs < 600
    tick_at = data.index([tc[:tick]].pack('Q<'))
    return nil unless tick_at
    start = tick_at + 8
    cbyte = data.getbyte(start)
    return nil if cbyte.nil? || cbyte == 0xFF || cbyte.odd?
    [cbyte >> 1, start + 1, data.bytesize - 8, data]
  end

  # Walk actions from `off`, consuming each payload from `lens`. Stops at the
  # first action whose type has no known length.
  # → [actions, offset_after] where each action is [type, header_bytes, length]
  #   and the action that stopped the walk is included with length nil.
  def walk(data, off, count, lens)
    actions = []
    count.times do
      t = u16v(data, off) or return [actions, nil]
      d = u16v(data, off + t[0]) or return [actions, nil]
      hdr = t[0] + d[0]
      len = lens[t[1]]
      actions << [t[1], hdr, len]
      return [actions, nil] if len.nil?
      off += hdr + len
    end
    [actions, off]
  end

  # The type of the first action whose length is missing from `lens` (the hole a
  # measurement would fill), or nil when the closure is not walkable up to one.
  def hole_type(data, lens, exclude: nil)
    lens = walk_lens_for(data, lens, exclude)
    b = bounds(data)
    return nil unless b
    count, area_start, = b
    walked, off = walk(data, area_start, count, lens)
    return nil unless off.nil? # must have stopped, not completed
    walked.find { |(_, _, len)| len.nil? }&.first
  end

  # Candidate lengths for the first action whose type is missing from `lens`.
  # → Array of Integers, possibly empty (undecidable) or with more than one
  #   (ambiguous, and therefore not evidence of anything).
  def candidates(data, lens, max_len = 40, exclude: nil)
    lens = walk_lens_for(data, lens, exclude)
    b = bounds(data)
    return [] unless b
    count, area_start, area_end, = b
    walked, off = walk(data, area_start, count, lens)
    hole = walked.index { |(_, _, len)| len.nil? }
    return [] unless hole && off.nil? # the walk must have stopped, not completed
    idxs = walked.each_index.select { |i| walked[i][0] == walked[hole][0] }
    return [] unless idxs.size == 1 # two holes of the same type: ambiguous split
    idx = hole
    before = area_start + walked[0...idx].sum { |(_, hdr, len)| hdr + len }
    ds = before + walked[idx][1] # past this action's header
    remaining = count - idx - 1
    (0..max_len).select do |l|
      o = ds + l
      constrained = false
      good = remaining.zero? ? (o == area_end) : true
      remaining.times do
        h = u16v(data, o) or (good = false; break)
        d = u16v(data, o + h[0]) or (good = false; break)
        len = lens[h[1]]
        break if len.nil?
        constrained ||= len.positive?
        o += h[0] + d[0] + len
      end
      good && o == area_end && (remaining.zero? || constrained)
    end
  end

  # The length of the hole, or nil when the closure is not decidable. `lens` is
  # the corpus-wide knowledge; the type under test must be absent from it.
  def measure_length(data, lens, type)
    return nil unless hole_type(data, lens, exclude: type) == type # the hole must BE this type
    cands = candidates(data, lens, exclude: type)
    cands.size == 1 ? cands.first : nil
  end

  # One corpus pass: for every payload, find the hole (the first action with no
  # known length) and tally its candidate lengths under that type. A payload
  # whose closure is not walkable, or which admits more than one candidate, votes
  # for nothing. → {type => {length => closures}}
  def measure_all(paths, lens, code_parsed: [])
    tally = Hash.new { |h, k| h[k] = Hash.new(0) }
    each_payload(paths) do |data|
      # The parser's own content-defined lengths belong in the walk: build_terrain
      # is not in the table, so without them it is the "hole" in every closure it
      # appears in and the leftover gets charged to it (a flood of 26 = its
      # two-record length). They are computed from the layout, not from the
      # table, so using them here is not circular.
      walk = code_parsed.empty? ? lens : lens.merge(parsed_lengths(data, code_parsed))
      t = hole_type(data, walk)
      next unless t
      cands = candidates(data, walk)
      tally[t][cands.first] += 1 if cands.size == 1
    end
    tally
  end

  # Lengths the parser computed for `types` in this payload, keyed by type.
  def parsed_lengths(data, types)
    res = (FactorioProtocol.parse_udp_payload(data) rescue nil)
    out = {}
    res&.dig(:heartbeat)&.dig(:tick_closures).to_a.each do |tc|
      (tc[:actions] || []).each do |a|
        next if a[:hit_unknown] || a[:data].nil?
        out[a[:type]] = a[:data].bytesize if types.include?(a[:type])
      end
    end
    out
  end

  def each_payload(paths)
    require_relative '../lib/pcap'
    paths.each do |path|
      PcapReader.new(path).each_packet do |*_n, _ts, _sip, _dip, _sp, _dp, data, _frame|
        yield data
      end
    end
  end

  # → {length => decisive closures}, :verdict, :best, :votes, :runner_up
  # A length is DECIDED with ≥min_obs agreeing closures and a `margin`× lead over
  # the runner-up; a tie is two shapes sharing an ID, and picking one mis-parses
  # the other, so a tie is :ambiguous.
  def measure(paths, lens, type, min_obs: 5, margin: 3)
    tally = Hash.new(0)
    each_payload(paths) do |data|
      len = measure_length(data, lens, type)
      tally[len] += 1 if len
    end
    ranked = tally.sort_by { |_, n| -n }
    best, top = ranked.first
    second = ranked[1]&.last.to_i
    verdict = (best && top >= min_obs && second * margin < top) ? :measured : :ambiguous
    { tally: tally, verdict: verdict, best: best, votes: top, second: second }
  end
end
