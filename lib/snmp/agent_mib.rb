# frozen_string_literal: true
#
# Minimal in-memory managed object store used by the SNMP agent.

require 'snmp/varbind'

module SNMP
  class Agent

    # A tiny MIB: a sorted map of OID -> value.  Values are kept as
    # encodable SNMP objects (Integer, OctetString, ...).
    class ObjectStore
      include Enumerable

      def initialize
        @objects = {}
      end

      # Register +value+ at +oid+.  Plain Ruby integers/strings are wrapped
      # in SNMP types.
      def set(oid, value)
        @objects[ObjectId.new(oid).to_a] = wrap(value)
      end

      alias []= set

      def get(oid)
        @objects[ObjectId.new(oid).to_a]
      end

      alias [] get

      # OIDs are sorted lexicographically.
      def sorted_oids
        @objects.keys.sort
      end

      # The first registered OID strictly lexicographically greater than
      # +oid+ that satisfies +visible+ (or every OID when no block is
      # given).  Returns nil at the end of the MIB.
      def next_oid(oid)
        key = ObjectId.new(oid).to_a
        sorted_oids.each do |candidate|
          next if (ObjectId.new(candidate) <=> ObjectId.new(key)) <= 0
          return candidate if !block_given? || yield(candidate)
        end
        nil
      end

      def each
        @objects.each { |oid, value| yield(ObjectId.new(oid), value) }
      end

      private

      def wrap(value)
        case value
        when SNMP::Integer, OctetString, ObjectId, IpAddress, Counter32,
             Gauge32, Unsigned32, TimeTicks, Opaque, Counter64, Null
          value
        when ::Integer then Integer.new(value)
        when ::String then OctetString.new(value)
        else value
        end
      end
    end
  end
end
