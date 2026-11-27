module ClipOk
  def self.copy(text)
    IO.popen('pbcopy', 'w') { |io| io.write(text) }
  end
end
