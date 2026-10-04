# frozen_string_literal: true

module SNMP
  class ThresholdMonitor
    class InvalidSample < ArgumentError; end
    class InvalidConfiguration < ArgumentError; end

    class Event
      attr_reader :direction, :time, :value, :threshold, :sample,
                  :previous_sample, :sample_type

      def initialize(direction, time, value, threshold, sample,
                     previous_sample, sample_type)
        @direction = direction
        @time = time
        @value = value
        @threshold = threshold
        @sample = sample
        @previous_sample = previous_sample
        @sample_type = sample_type
      end

      def type
        direction
      end

      def event_type
        direction
      end

      def alarm_type
        direction
      end

      def timestamp
        time
      end

      def metric
        value
      end

      def rising?
        direction == :rising
      end

      def falling?
        direction == :falling
      end

      def to_h
        {
          :direction => direction,
          :time => time,
          :value => value,
          :threshold => threshold,
          :sample => sample,
          :previous_sample => previous_sample,
          :sample_type => sample_type
        }
      end

      def to_s
        "#{direction} threshold event: #{value} at #{time}"
      end
    end

    Sample = Struct.new(:time, :value, :width, :discontinuity)

    attr_reader :sample_type, :rising_threshold, :falling_threshold,
                :first_sample_policy

    def initialize(options = {}, &callback)
      @sample_type = normalize_sample_type(option(options, :mode, :type,
                                                  :sample_type,
                                                  :sampleType) || :absolute)
      @rising_threshold = threshold_option(options, :rising_threshold,
                                           :rising, :risingThreshold,
                                           :rising_event_threshold)
      @falling_threshold = threshold_option(options, :falling_threshold,
                                            :falling, :fallingThreshold,
                                            :falling_event_threshold)
      validate_thresholds
      @first_sample_policy = normalize_first_sample_policy(option(
        options, :first_sample, :firstSample, :first_sample_policy,
        :startup_alarm, :startupAlarm, :startup
      ))
      @on_event = options[:on_event] || options[:on_alarm] || callback
      reset
    end

    UNSPECIFIED = Object.new.freeze

    def feed(time_or_sample, raw_value = UNSPECIFIED, width = 32,
             discontinuity = false)
      sample = if raw_value.equal?(UNSPECIFIED)
                 time_or_sample
               else
                 Sample.new(time_or_sample, raw_value, width, discontinuity)
               end
      time = sample_attribute(sample, :time, :timestamp, :sample_time)
      raw_value = sample_attribute(sample, :value, :counter, :count)
      width = normalize_width(sample_attribute(
        sample, :width, :counter_width, :counterWidth, :bit_width, :bits
      ))
      discontinuity = boolean_attribute(sample_attribute(
        sample, :discontinuity, :discontinuity?, :discontinuous, :reset,
        :reset?
      ))

      raise InvalidSample, "sample value is required" if raw_value.nil?
      value = integer_value(raw_value, "sample value")
      validate_counter_value(value, width)

      restart = @first_sample || discontinuity || width != @width
      if restart
        event = restart_sample(sample, time, value, width)
      else
        metric = sampled_value(value)
        event = detect_event(metric, time, sample)
        set_armed_state(metric)
      end

      @previous_sample = sample
      @previous_value = value
      @width = width
      @first_sample = false

      dispatch(event)
      event
    end
    alias_method :feed_sample, :feed
    alias_method :observe, :feed
    alias_method :add_sample, :feed
    alias_method :process, :feed
    alias_method :<<, :feed

    def feed_many(samples)
      samples.map { |sample| feed(sample) }.compact
    end
    alias_method :feed_samples, :feed_many
    alias_method :process_many, :feed_many
    alias_method :feed_all, :feed_many

    def reset
      @previous_sample = nil
      @previous_value = nil
      @width = nil
      @first_sample = true
      @rising_armed = true
      @falling_armed = true
    end

    private

    def option(options, *names)
      names.each do |name|
        return options[name] if options.key?(name)
        return options[name.to_s] if options.key?(name.to_s)
      end
      nil
    end

    def threshold_option(options, *names)
      value = option(options, *names)
      value ||= option(options[:thresholds] || {}, *names)
      return nil if value.nil?
      configuration_integer(value, "threshold")
    end

    def normalize_sample_type(value)
      case canonical_name(value)
      when :absolute, :absolute_value, :"1"
        :absolute
      when :delta, :delta_value, :"2"
        :delta
      else
        raise InvalidConfiguration, "unsupported sample type: #{value.inspect}"
      end
    end

    def normalize_first_sample_policy(value)
      normalized_name = value.is_a?(::Symbol) || value.is_a?(::String) ?
        canonical_name(value) : nil
      return :rising_or_falling if value == true || normalized_name == :true
      return :none if value == false || normalized_name == :false

      case canonical_name(value || :rising_or_falling)
      when :rising, :rising_sent, :rising_sent_alarm, :"1"
        :rising
      when :falling, :falling_sent, :falling_sent_alarm, :"2"
        :falling
      when :rising_or_falling, :either, :rising_or_falling_sent,
           :rising_or_falling_alarm, :rising_and_falling, :both, :all, :"3"
        :rising_or_falling
      when :none, :ignore, :skip, :skip_first, :baseline, :suppress,
           :no_startup, :no_alarm, :no_alarms
        :none
      when :zero, :evaluate
        :zero
      else
        raise InvalidConfiguration,
              "unsupported first sample policy: #{value.inspect}"
      end
    end

    def canonical_name(value)
      case value
      when ::Symbol, ::String
        value.to_s.gsub(/([a-z\d])([A-Z])/, '\\1_\\2')
             .downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_|_$/, '').to_sym
      when ::Integer
        value.to_s.to_sym
      else
        value
      end
    end

    def validate_thresholds
      return if @rising_threshold.nil? || @falling_threshold.nil?
      if @rising_threshold <= @falling_threshold
        raise InvalidConfiguration,
              "rising threshold must be greater than falling threshold"
      end
    end

    def sample_attribute(sample, *names)
      names.each do |name|
        if sample.respond_to?(:key?)
          if sample.key?(name)
            return sample[name]
          elsif sample.key?(name.to_s)
            return sample[name.to_s]
          end
        end

        if sample.respond_to?(name)
          value = sample.public_send(name)
          return value unless value.nil?
        end
      end
      nil
    end

    def boolean_attribute(value)
      case value
      when nil, false, 0
        false
      when ::String, ::Symbol
        !%w[0 false no off].include?(value.to_s.downcase)
      else
        true
      end
    end

    def integer_value(value, description)
      if value.is_a?(::String)
        Kernel.Integer(value)
      elsif value.is_a?(::Numeric)
        converted = value.to_i
        raise InvalidSample, "#{description} must be an integer" unless converted == value
        converted
      elsif value.respond_to?(:to_i) && !value.is_a?(::Symbol)
        value.to_i
      else
        raise InvalidSample, "#{description} must be an integer"
      end
    rescue ArgumentError, RangeError
      raise InvalidSample, "#{description} is out of range"
    end

    def configuration_integer(value, description)
      integer_value(value, description)
    rescue InvalidSample
      raise InvalidConfiguration, "#{description} must be an integer"
    end

    def normalize_width(width)
      case width
      when nil
        32
      when ::Integer
        width
      when ::String, ::Symbol
        match = width.to_s.downcase.match(/\Acounter?(?<bits>\d+)\z|\A(?<bits2>\d+)\z/)
        match ? (match[:bits] || match[:bits2]).to_i :
          raise(InvalidSample, "unsupported counter width: #{width.inspect}")
      else
        raise InvalidSample, "unsupported counter width: #{width.inspect}"
      end.tap do |resolved_width|
        unless [8, 16, 32, 64].include?(resolved_width)
          raise InvalidSample, "counter width must be 8, 16, 32, or 64"
        end
      end
    end

    def validate_counter_value(value, width)
      return if value >= 0 && value < (1 << width)
      raise InvalidSample,
            "counter value #{value} is outside a #{width}-bit counter"
    end

    def restart_sample(sample, time, value, width)
      @width = width
      if sample_type == :absolute
        prepare_startup_alarms
        event = detect_event(value, time, sample)
        set_armed_state(value)
        event
      else
        @rising_armed = true
        @falling_armed = true
        if first_sample_policy == :zero
          prepare_startup_alarms
          event = detect_event(0, time, sample)
          set_armed_state(0)
          event
        end
      end
    end

    def prepare_startup_alarms
      case first_sample_policy
      when :rising
        @rising_armed = true
        @falling_armed = false
      when :falling
        @rising_armed = false
        @falling_armed = true
      when :none
        @rising_armed = false
        @falling_armed = false
      else
        @rising_armed = true
        @falling_armed = true
      end
    end

    def sampled_value(value)
      if sample_type == :absolute
        value
      else
        modulus = 1 << @width
        (value - @previous_value) % modulus
      end
    end

    def detect_event(metric, time, sample)
      if rising_threshold && metric >= rising_threshold && @rising_armed
        Event.new(:rising, time, metric, rising_threshold, sample,
                  @previous_sample, sample_type)
      elsif falling_threshold && metric <= falling_threshold && @falling_armed
        Event.new(:falling, time, metric, falling_threshold, sample,
                  @previous_sample, sample_type)
      end
    end

    def set_armed_state(metric)
      @rising_armed = rising_threshold.nil? ? false : metric < rising_threshold
      @falling_armed = falling_threshold.nil? ? false : metric > falling_threshold
    end

    def dispatch(event)
      return unless event && @on_event
      @on_event.call(event)
    end
  end

  ThresholdEvent = ThresholdMonitor::Event
  CounterSample = ThresholdMonitor::Sample
end
