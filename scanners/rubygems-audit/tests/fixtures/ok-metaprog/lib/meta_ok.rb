module MetaOk
  %w[name email].each do |attr|
    class_eval <<-RUBY, __FILE__, __LINE__ + 1
      def #{attr}(*params)
        @#{attr} = params.first if params.any?
        @#{attr}
      end
    RUBY
  end

  def self.load_config(path)
    instance_eval(File.read(path), path)
  end

  def self.configure(&block)
    instance_eval(&block)
  end

  def self.filter(params)
    params[:q].to_s.strip
  end
end
