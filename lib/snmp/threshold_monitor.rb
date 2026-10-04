# frozen_string_literal: true

module SNMP
  class CounterSample
    attr_reader :timestamp, :value, :width

    def initialize(timestamp, value, options={}, discontinuity=nil)
      @timestamp = timestamp
      @value = value.kind_of?(Integer) ? value.to_i : Integer(value)
      options = sample_options(options, discontinuity)
      @width = options[:width] || options[:counter_width] || options[:bits] || 32
      @width = Integer(@width)
      @discontinuity = options[:discontinuity] || options[:reset] || false

      unless @width >= 1 && @width <= 64
        raise ArgumentError, "counter width must be between 1 and 64: #{@width}"
      end
      unless @value >= 0 && @value < (1 << @width)
        raise ArgumentError, "counter value is out of range for a #{@width}-bit counter: #{@value}"
      end
    end

    def discontinuity?
      !!@discontinuity
    end
    alias_method :reset?, :discontinuity?
    alias_method :time, :timestamp
    alias_method :counter, :value
    alias_method :counter_width, :width

    private

    def sample_options(options, discontinuity)
      if options.kind_of?(Numeric)
        options = { :width => options }
      elsif options == true || options == false
        options = { :discontinuity => options }
      else
        options = (options || {}).dup
      end
      options[:discontinuity] = discontinuity unless discontinuity.nil?
      options
    end
  end

  class ThresholdEvent
    attr_reader :direction, :mode, :metric, :threshold, :timestamp, :sample, :previous_sample

    def initialize(direction, mode, metric, threshold, sample, previous_sample)
      @direction = direction
      @mode = mode
      @metric = metric
      @threshold = threshold
      @timestamp = sample.timestamp
      @sample = sample
      @previous_sample = previous_sample
    end

    def rising?
      @direction == :rising
    end

    def falling?
      @direction == :falling
    end

    def to_sym
      @direction
    end

    def to_s
      @direction.to_s
    end
    alias_method :type, :direction
    alias_method :name, :to_sym
    alias_method :time, :timestamp
    alias_method :value, :metric

    def inspect
      "#<SNMP::ThresholdEvent #{@direction} #{@metric} @ #{@timestamp.inspect}>"
    end
  end

  class ThresholdMonitor
    attr_reader :mode, :rising_threshold, :falling_threshold, :startup_alarms,
                :counter_width

    def initialize(configuration={}, overrides={})
      unless configuration.kind_of?(Hash)
        configuration = overrides.merge(:mode => configuration)
      end
      config = configuration.dup.merge(overrides)

      @mode = normalize_mode(config[:mode] || config[:metric] || :absolute)
      mode_config = config[@mode]
      config = mode_config.merge(config) if mode_config.kind_of?(Hash)

      @rising_threshold = extract_threshold(config, :rising)
      @falling_threshold = extract_threshold(config, :falling)
      @counter_width = config[:counter_width] || config[:width] || config[:bits] || 32
      validate_thresholds

      @startup_alarms = normalize_startup_alarms(config)
      @state = nil
      @last_sample = nil
      @event_handlers = {
        :event => Array(config[:on_event]),
        :rising => Array(config[:on_rising]),
        :falling => Array(config[:on_falling])
      }
    end

    def feed(*arguments, &block)
      sample = coerce_sample(*arguments)
      if @last_sample && timestamps_out_of_order?(@last_sample, sample)
        raise ArgumentError, "samples must be supplied in timestamp order"
      end

      reset_state = sample.discontinuity?
      if absolute?
        events = if reset_state || @last_sample.nil?
                   startup_event(sample, startup_metric(sample), reset_state)
                 else
                   evaluate(sample, sample.value)
                 end
      else
        events = delta_events(sample, reset_state)
      end

      @last_sample = sample
      events.each do |event|
        block.call(event) if block
        @event_handlers[:event].each { |handler| handler.call(event) }
        @event_handlers[event.direction].each { |handler| handler.call(event) }
      end
      events
    end
    alias_method :feed_sample, :feed
    alias_method :<<, :feed

    def on_event(&block)
      raise ArgumentError, "a block must be provided" unless block
      @event_handlers[:event] << block
    end

    def on_rising(&block)
      raise ArgumentError, "a block must be provided" unless block
      @event_handlers[:rising] << block
    end

    def on_falling(&block)
      raise ArgumentError, "a block must be provided" unless block
      @event_handlers[:falling] << block
    end

    def absolute?
      @mode == :absolute
    end

    def delta?
      @mode == :delta
    end

    def last_sample
      @last_sample
    end

    private

    def delta_events(sample, reset_state)
      if reset_state || @last_sample.nil?
        if @startup_alarms == :baseline
          @state = nil
          []
        elsif @startup_alarms == :zero
          startup_event(sample, 0, reset_state)
        else
          startup_event(sample, sample.value, reset_state)
        end
      else
        modulus = 1 << sample.width
        delta = (sample.value - @last_sample.value) % modulus
        evaluate(sample, delta, @last_sample)
      end
    end

    def evaluate(sample, metric, previous_sample=@last_sample)
      new_state = state_for(metric)
      if new_state && new_state != @state
        threshold = new_state == :rising ? @rising_threshold : @falling_threshold
        @state = new_state
        [ThresholdEvent.new(new_state, @mode, metric, threshold, sample, previous_sample)]
      else
        @state = new_state
        []
      end
    end

    def startup_event(sample, metric, reset_state)
      @state = nil if reset_state
      new_state = state_for(metric)
      allowed = allowed_startup_alarms(new_state)
      if new_state && allowed
        threshold = new_state == :rising ? @rising_threshold : @falling_threshold
        @state = new_state
        [ThresholdEvent.new(new_state, @mode, metric, threshold, sample, @last_sample)]
      else
        @state = new_state
        []
      end
    end

    def allowed_startup_alarms(state)
      case @startup_alarms
      when :both then true
      when :rising then state == :rising
      when :falling then state == :falling
      when :baseline then false
      when :zero then true
      else false
      end
    end

    def startup_metric(sample)
      @startup_alarms == :zero ? 0 : sample.value
    end

    def state_for(metric)
      if @rising_threshold && metric >= @rising_threshold
        :rising
      elsif @falling_threshold && metric <= @falling_threshold
        :falling
      elsif both_thresholds?
        @state
      else
        nil
      end
    end

    def both_thresholds?
      !!@rising_threshold && !!@falling_threshold
    end

    def normalize_mode(mode)
      case mode.to_s
      when 'absolute', 'abs', 'value' then :absolute
      when 'delta', 'difference', 'counter_delta' then :delta
      else raise ArgumentError, "unsupported monitor mode: #{mode.inspect}"
      end
    end

    def normalize_startup_alarms(config)
      value = config[:startup_alarms] || config[:startup] ||
        config[:first_sample] || config[:startup_alarm]
      value = :rising_or_falling if value.nil? && absolute?
      value = :baseline if value.nil? && delta?

      case value
      when ::Integer
        case value
        when 0 then :baseline
        when 1 then :rising
        when 2 then :falling
        when 3 then :both
        else raise ArgumentError, "unsupported first-sample strategy: #{value.inspect}"
        end
      else
        case value.to_s
        when 'both', 'rising_or_falling', 'risingOrFalling', 'either', 'all',
             'evaluate', 'normal', 'true'
          :both
        when 'rising', 'high' then :rising
        when 'falling', 'low' then :falling
        when 'baseline', 'skip', 'ignore', 'never', 'none', 'false' then :baseline
        when 'zero', 'zero_delta' then :zero
        else raise ArgumentError, "unsupported first-sample strategy: #{value.inspect}"
        end
      end
    end

    def extract_threshold(config, direction)
      keys = [
        :"#{direction}_threshold",
        :"#{direction}Threshold",
        direction,
        :"#{direction}_limit"
      ]
      value = keys.map { |key| config[key] }.compact.first
      return nil if value.nil?
      raise ArgumentError, "#{direction} threshold must be numeric" unless value.kind_of?(Numeric)
      value
    end

    def validate_thresholds
      if @rising_threshold.nil? && @falling_threshold.nil?
        raise ArgumentError, "at least one threshold must be configured"
      end
      if both_thresholds? && @rising_threshold <= @falling_threshold
        raise ArgumentError, "rising threshold must be greater than falling threshold"
      end
    end

    def coerce_sample(first=nil, second=nil, options={}, fourth=nil)
      return first if first.kind_of?(CounterSample)

      if first.kind_of?(Hash)
        options = first.merge(options || {})
        timestamp = options[:timestamp] || options[:time]
        value = options[:value] || options[:counter]
        options[:width] ||= @counter_width
        return CounterSample.new(timestamp, value, options)
      end

      if second.nil?
        options = (options || {}).dup
        options[:width] ||= @counter_width
        CounterSample.new(nil, first, options)
      else
        if options.kind_of?(Numeric)
          options = { :width => options }
        elsif options == true || options == false
          options = { :discontinuity => options }
        else
          options = (options || {}).dup
        end
        options[:discontinuity] = fourth unless fourth.nil?
        options[:width] ||= @counter_width
        CounterSample.new(first, second, options)
      end
    end

    def timestamps_out_of_order?(previous_sample, sample)
      previous_sample.timestamp && sample.timestamp &&
        sample.timestamp < previous_sample.timestamp
    end
  end

  CounterThresholdMonitor = ThresholdMonitor
end
