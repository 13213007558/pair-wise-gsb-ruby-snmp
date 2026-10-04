# frozen_string_literal: true

require 'minitest/autorun'
require 'snmp/varbind'
require 'snmp/threshold_monitor'

class TestThresholdMonitor < Minitest::Test
  include SNMP

  def sample(time, value, options = {})
    attributes = {
      :time => time,
      :value => value,
      :width => options.fetch(:width, 32),
      :discontinuity => options.fetch(:discontinuity, false)
    }
    if options[:object]
      ThresholdMonitor::Sample.new(attributes[:time], attributes[:value],
                                   attributes[:width], attributes[:discontinuity])
    else
      attributes
    end
  end

  def events_for(monitor, samples)
    monitor.feed_many(samples).map(&:direction)
  end

def test_absolute_rising_event_only_once_until_falling_resets_it
  monitor = ThresholdMonitor.new(
    :mode => :absolute,
    :rising_threshold => 10,
      :falling_threshold => 5,
      :first_sample => :none
    )

    assert_nil(monitor.feed(sample(0, 0)))
    event = monitor.feed(sample(1, 10))
    assert_equal(:rising, event.direction)
    assert_equal(10, event.value)
    assert_equal(10, event.threshold)
    assert_equal(1, event.time)
    assert_equal(:absolute, event.sample_type)
    assert_nil(monitor.feed(sample(2, 11)))
    assert_nil(monitor.feed(sample(3, 10)))
    assert_nil(monitor.feed(sample(4, 6)))

    falling_event = monitor.feed(sample(5, 5))
    assert_equal(:falling, falling_event.direction)
    assert_nil(monitor.feed(sample(6, 4)))

    assert_equal(:rising, monitor.feed(sample(7, 10)).direction)
  end

def test_delta_monitor_uses_counter32_wrap_around
  monitor = ThresholdMonitor.new(
    :mode => :delta,
    :rising_threshold => 4,
      :falling_threshold => 0,
      :first_sample => :none
    )

    assert_nil(monitor.feed(sample(0, 4_294_967_295)))

    event = monitor.feed(sample(1, 3))
    assert_equal(:rising, event.direction)
    assert_equal(4, event.value)
    assert_nil(monitor.feed(sample(2, 13)))
  end

  def test_discontinuity_reestablishes_delta_baseline
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 10,
      :falling_threshold => 0,
      :first_sample => :none
    )
    samples = [
      sample(0, 100),
      sample(1, 120),
      sample(2, 0, :discontinuity => true),
      sample(3, 9),
      sample(4, 20)
    ]

    assert_equal([:rising, :rising], events_for(monitor, samples))
  end

  def test_counter_width_change_is_treated_as_discontinuity
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 10,
      :falling_threshold => 0,
      :first_sample => :none
    )

    assert_nil(monitor.feed(sample(0, 250, :width => 8)))
    assert_nil(monitor.feed(sample(1, 255, :width => 8)))
    assert_nil(monitor.feed(sample(2, 8, :width => 32)))
    assert_equal(:rising, monitor.feed(sample(3, 18, :width => 32)).direction)
  end

  def test_startup_rising_policy
    assert_equal([:rising], events_for(
      ThresholdMonitor.new(
        :mode => :absolute,
        :rising_threshold => 10,
        :falling_threshold => 5,
        :first_sample => :rising
      ),
      [sample(0, 4), sample(1, 11)]
    ))
  end

  def test_startup_falling_policy
    assert_equal([:falling], events_for(
      ThresholdMonitor.new(
        :mode => :absolute,
        :rising_threshold => 10,
        :falling_threshold => 5,
        :first_sample => :falling
      ),
      [sample(0, 11), sample(1, 4)]
    ))
  end

  def test_startup_rising_or_falling_policy
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 10,
      :falling_threshold => 5,
      :first_sample => :rising_or_falling
    )

    assert_equal(:rising, monitor.feed(sample(0, 11)).direction)
    assert_nil(monitor.feed(sample(1, 6)))
  end

  def test_delta_first_sample_can_be_ignored_or_evaluated_as_zero
    suppressed = ThresholdMonitor.new(
      :mode => :delta,
      :falling_threshold => 0,
      :first_sample => :none
    )
    assert_nil(suppressed.feed(sample(0, 0)))

    evaluated = ThresholdMonitor.new(
      :mode => :delta,
      :falling_threshold => 0,
      :first_sample => :zero
    )
    event = evaluated.feed(sample(0, 0))
    assert_equal(:falling, event.direction)
    assert_equal(0, event.value)
  end

  def test_discontinuity_reapplies_first_sample_policy
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 10,
      :falling_threshold => 0,
      :first_sample => :none
    )

    monitor.feed(sample(0, 11))
    monitor.feed(sample(1, 20))
    monitor.feed(sample(2, 30, :discontinuity => true))
    assert_nil(monitor.feed(sample(3, 31)))
  end

  def test_callback_and_sample_object
    received = []
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 10,
      :falling_threshold => 0,
      :first_sample => :rising
    ) do |event|
      received << event
    end

    first_sample = sample(0, 11, :object => true)
    monitor << first_sample

    assert_equal(1, received.length)
    assert_equal(first_sample, received.first.sample)
    assert_equal(first_sample, monitor.feed_many([sample(1, 0,
                                                        :object => true),
                                                sample(2, 10,
                                                        :object => true)])
                  .first.previous_sample)
  end

  def test_accepts_snmp_counter_value
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 4,
      :falling_threshold => 0,
      :first_sample => :none
    )
    counter_sample = ThresholdMonitor::Sample.new(0,
                                                  SNMP::Counter32.new(4_294_967_295),
                                                  32, false)

    monitor.feed(counter_sample)
    event = monitor.feed(ThresholdMonitor::Sample.new(1,
                                                      SNMP::Counter32.new(3),
                                                      32, false))
    assert_equal(4, event.value)
  end

  def test_rejects_invalid_counter_value_and_width
    monitor = ThresholdMonitor.new(:mode => :delta)

    assert_raises(ThresholdMonitor::InvalidSample) do
      monitor.feed(sample(0, 4_294_967_296))
    end
    assert_raises(ThresholdMonitor::InvalidSample) do
      monitor.feed(sample(0, -1))
    end
    assert_raises(ThresholdMonitor::InvalidSample) do
      monitor.feed(sample(0, 1, :width => 12))
    end
  end

  def test_rejects_thresholds_that_cannot_create_hysteresis
    assert_raises(ThresholdMonitor::InvalidConfiguration) do
      ThresholdMonitor.new(
        :mode => :absolute,
        :rising_threshold => 5,
        :falling_threshold => 5
      )
    end
  end

  def test_configuration_aliases_and_defaults
    monitor = ThresholdMonitor.new(
      "sampleType" => "deltaValue",
      "risingThreshold" => "4",
      "fallingThreshold" => "0",
      "firstSample" => false
    )

    assert_equal(:delta, monitor.sample_type)
    assert_equal(4, monitor.rising_threshold)
    assert_equal(0, monitor.falling_threshold)
    assert_equal(:none, monitor.first_sample_policy)
  end

  def test_numeric_startup_policy_and_counter64_width
    monitor = ThresholdMonitor.new(
      :mode => 2,
      :rising_threshold => 2,
      :falling_threshold => 0,
      :first_sample => 1
    )

    monitor.feed(sample(0, 18_446_744_073_709_551_614, :width => 64))
    event = monitor.feed(sample(1, 1, :width => 64))
    assert_equal(:rising, event.direction)
    assert_equal(3, event.value)
    assert_equal(1, event.timestamp)
    assert_equal(3, event.metric)
  end

  def test_default_sample_type_is_absolute
    monitor = ThresholdMonitor.new(:rising_threshold => 5,
                                   :falling_threshold => 0)
    assert_equal(:rising, monitor.feed(sample(0, 5)).direction)
  end

  def test_non_integer_threshold_is_configuration_error
    assert_raises(ThresholdMonitor::InvalidConfiguration) do
      ThresholdMonitor.new(:rising_threshold => 1.5)
    end
  end

  def test_positional_samples_nested_thresholds_and_on_alarm
    received = []
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :thresholds => {
        :rising => 4,
        :falling => 0
      },
      :first_sample => :skip_first,
      :on_alarm => proc { |event| received << event }
    )

    assert_nil(monitor.feed(0, 10, 32, false))
    event = monitor.feed(1, 14, 32, false)
    assert_equal(:rising, event.direction)
    assert_equal(event, received.first)
  end

  def test_positional_zero_value_is_not_treated_as_a_sample_object
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :falling_threshold => 0,
      :first_sample => :zero
    )

    event = monitor.feed(0, 0, 32, false)
    assert_equal(:falling, event.direction)
    assert_equal(0, event.value)
  end
end
