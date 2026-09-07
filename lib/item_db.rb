# Build item prototype lookup from a runtime dump of item names in wire-id
# order (external/item_prototypes_runtime.txt, regenerable via
# tools/item_db.rb from a live server's RCON).

class ItemDB
  def initialize(path)
    @items = {}  # id -> name
    File.read(path).each_line do |line|
      next unless line =~ /^(\d+)\s*=\s*(.+)$/
      @items[$1.to_i] = $2.strip
    end
  end

  def name(id)
    @items[id] || "unknown(#{id})"
  end

  def size
    @items.size
  end
end
