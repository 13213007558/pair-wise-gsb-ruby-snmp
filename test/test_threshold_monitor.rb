# frozen_string_literal: true

require 'minitest/autorun'
require 'snmp/threshold_monitor'

class TestThresholdMonitor < Minitest::Test
  include SNMP

  def test_absolute_thresholds_use_hysteresis_and_edge_reporting
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 80,
      :falling_threshold => 70,
      :startup_alarms => :ignore
    )
    events = feed(monitor, [70, 79, 80, 90, 80, 75, 70, 79])

    assert_equal([:rising, :falling], events.map(&:direction))
    assert_equal([80, 70], events.map(&:metric))
    assert_equal([80, 70], events.map(&:threshold))
    assert_equal([2, 6], events.map(&:timestamp))
  end

  def test_absolute_first_sample_alarms
    rising = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 80,
      :falling_threshold => 70,
      :startup_alarms => :rising
    )
    assert_equal([:rising], feed(rising, [85, 90]).map(&:direction))

    falling = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 80,
      :falling_threshold => 70,
      :startup_alarms => :falling
    )
    assert_equal([:falling, :rising], feed(falling, [65, 60, 85]).map(&:direction))

    either = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 80,
      :falling_threshold => 70,
      :startup_alarms => :rising_or_falling
    )
    assert_equal([:falling], feed(either, [65, 60]).map(&:direction))
  end

  def test_absolute_ignore_first_sample_establishes_state_without_event
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 80,
      :falling_threshold => 70,
      :startup_alarms => :ignore
    )

    assert_equal([:falling], feed(monitor, [85, 70]).map(&:direction))

    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 80,
      :falling_threshold => 70,
      :startup_alarms => :ignore
    )
    assert_equal([], feed(monitor, [85, 90]).map(&:direction))
  end

  def test_delta_uses_first_sample_as_baseline
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 5,
      :falling_threshold => 0,
      :startup_alarms => :baseline
    )
    events = feed(monitor, [10, 12, 20, 24, 21])

    assert_equal([:rising], events.map(&:direction))
    assert_equal(8, events.first.metric)
    assert_equal(12, events.first.previous_sample.value)
  end

  def test_counter32_wraparound_is_handled_as_a_delta
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 10,
      :falling_threshold => 0
    )

    assert_empty(monitor.feed(CounterSample.new(0, 4_294_967_290, :width => 32)))
    event = monitor.feed(CounterSample.new(1, 5, :width => 32)).first

    assert_equal(:rising, event.direction)
    assert_equal(11, event.metric)
  end

  def test_counter_sample_accepts_positional_width_and_discontinuity
    sample = CounterSample.new(3, 5, 32, true)

    assert_equal(3, sample.timestamp)
    assert_equal(5, sample.value)
    assert_equal(32, sample.width)
    assert(sample.discontinuity?)

    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 2,
      :falling_threshold => 0
    )
    monitor.feed(0, 100, 32)
    monitor.feed(1, 10, true)
    monitor.feed(2, 11, 32, false)
    event = monitor.feed(3, 15, 32).first

    assert_equal(:rising, event.direction)
    assert_equal(4, event.metric)
    assert_equal("rising", event.to_s)
    assert_equal(:rising, event.type)
  end

  def test_discontinuity_rebuilds_delta_baseline
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 2,
      :falling_threshold => 0
    )

    assert_empty(monitor.feed(0, 100))
    assert_empty(monitor.feed(1, 10, :discontinuity => true))
    event = monitor.feed(2, 13).first

    assert_equal(:rising, event.direction)
    assert_equal(3, event.metric)
    assert(monitor.last_sample.timestamp == 2)
  end

  def test_hash_samples_and_registered_callbacks_are_supported
    received = []
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 2,
      :falling_threshold => 0,
      :startup_alarms => :ignore,
      :on_rising => lambda { |event| received << event }
    )

    events = monitor.feed(:timestamp => 1, :value => 1, :width => 32)
    assert_empty(events)
    events = monitor.feed(:timestamp => 2, :counter => 2, :counter_width => 32)
    assert_equal([:rising], events.map(&:direction))
    assert_equal(events, received)
  end

  def test_rising_only_threshold_resets_silently_below_the_threshold
    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 10,
      :startup_alarms => :ignore
    )

    assert_equal([:rising, :rising], feed(monitor, [5, 10, 5, 10]).map(&:direction))
  end

  def test_mode_specific_threshold_configuration
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :delta => {
        :rising_threshold => 2,
        :falling_threshold => 0,
        :startup_alarms => :baseline
      }
    )

    assert_equal([:rising], feed(monitor, [0, 3]).map(&:direction))
  end

  def test_zero_startup_strategy_and_numeric_aliases
    monitor = ThresholdMonitor.new(
      :mode => :delta,
      :rising_threshold => 1,
      :falling_threshold => 0,
      :startup_alarms => :zero
    )

    assert_equal([:falling], monitor.feed(0, 0).map(&:direction))
    assert_equal([:rising], monitor.feed(1, 1).map(&:direction))

    monitor = ThresholdMonitor.new(
      :mode => :absolute,
      :rising_threshold => 10,
      :falling_threshold => 0,
      :startup_alarms => 1
    )
    assert_empty(monitor.feed(0, 0))
    assert_equal([:rising], monitor.feed(1, 10).map(&:direction))
  end

  def test_rejects_samples_out_of_timestamp_order
    monitor = ThresholdMonitor.new(:rising_threshold => 1)
    monitor.feed(2, 0)

    assert_raises(ArgumentError) { monitor.feed(1, 1) }
  end

  def test_rejects_invalid_counter_values_and_threshold_configuration
    assert_raises(ArgumentError) do
      CounterSample.new(0, 4_294_967_296, :width => 32)
    end
    assert_raises(ArgumentError) do
      ThresholdMonitor.new(:rising_threshold => 1, :falling_threshold => 2)
    end
    assert_raises(ArgumentError) do
      ThresholdMonitor.new(:startup_alarms => :bogus)
    end
  end

  private

  def feed(monitor, values)
    values.each_with_index.flat_map do |value, index|
      monitor.feed(index, value)
    end
  end
end
