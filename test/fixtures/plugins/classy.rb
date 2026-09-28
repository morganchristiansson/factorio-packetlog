# A feature that is a CLASS the host instantiates (hivemind, translation
# today): it contributes no module, and apply_mixins must skip it.
class Classy
  def self.online? = true
end
