# frozen_string_literal: true
#
# Copyright (c) 2004-2014 David R. Halliday
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

require 'snmp/varbind'

module SNMP

  ##
  # A minimal View-based Access Control Model (VACM, RFC 3415) for the
  # SNMP agent.  Access is decided in two steps:
  #
  # 1. Select a vacmAccessTable entry from the security name, security
  #    model, security level, context, and the requested operation
  #    (:read, :write, or :notify).  The entry yields the view name to
  #    use for that operation.
  # 2. Check the OID against the vacmViewTreeFamilyTable entries of that
  #    view, honoring the per-entry mask.  The longest matching subtree
  #    decides whether the OID is inside or outside the view.
  #
  # Example
  #
  #   vacm = SNMP::VACM.new
  #   vacm.add_security_to_group(security_model: :snmpv2c,
  #                              security_name: "public",
  #                              group_name: "ro")
  #   vacm.add_access(group_name: "ro", security_model: :snmpv2c,
  #                   read_view: "system")
  #   vacm.add_view_subtree("system", "1.3.6.1.2.1.1")
  #   decision = vacm.decide(operation: :read, oid: "1.3.6.1.2.1.1.5.0",
  #                          security_model: 2, security_name: "public")
  #   decision.allowed?  # => true
  #   decision.view_name # => "system"
  #
  class VACM

    SECURITY_LEVELS = {
      noAuthNoPriv: 1,
      authNoPriv: 2,
      authPriv: 3
    }.freeze

    SECURITY_MODELS = {
      any: 0,
      snmpv1: 1,
      snmpv2c: 2,
      snmpv2: 2,
      usm: 3,
      snmpv3: 3
    }.freeze

    ## Security model wildcard (matches any model in table lookups).
    ANY_MODEL = SECURITY_MODELS[:any]

    ##
    # One row of the vacmAccessTable.
    #
    AccessEntry = Struct.new(
      :group_name, :context_prefix, :security_model, :security_level,
      :context_match, :read_view, :write_view, :notify_view
    ) do
      def view_for(operation)
        case operation
        when :read   then read_view
        when :write  then write_view
        when :notify then notify_view
        else
          raise ArgumentError, "unknown operation: #{operation.inspect}"
        end
      end
    end

    ##
    # One row of the vacmViewTreeFamilyTable: a subtree, a mask, and a
    # type (:included or :excluded) belonging to a named view.
    #
    ViewSubtree = Struct.new(:view_name, :subtree, :mask, :type) do
      def included?
        type == :included
      end
    end

    ##
    # The outcome of an access check.  Exposes the selected group, access
    # entry, and view so callers (and tests) can verify exactly which
    # configuration rows produced the decision.
    #
    class AccessDecision
      attr_reader :status, :operation, :oid, :security_model, :security_name,
                  :security_level, :context_name, :group_name, :access_entry,
                  :view_name

      def initialize(status, operation:, oid:, security_model:, security_name:,
                     security_level:, context_name:, group_name: nil,
                     access_entry: nil, view_name: nil)
        @status = status
        @operation = operation
        @oid = oid
        @security_model = security_model
        @security_name = security_name
        @security_level = security_level
        @context_name = context_name
        @group_name = group_name
        @access_entry = access_entry
        @view_name = view_name
      end

      def allowed?
        @status == :ok
      end

      def to_s
        verdict = allowed? ? "allow" : "deny"
        parts = ["VACM #{verdict}(#{@status})",
                 "op=#{@operation}",
                 "oid=#{@oid}",
                 "security=#{@security_name}/#{@security_model}/#{@security_level}",
                 "context=#{@context_name.inspect}"]
        parts << "group=#{@group_name}" if @group_name
        if @access_entry
          entry = @access_entry
          parts << "access=(#{entry.group_name},#{entry.context_prefix.inspect}," \
                   "#{entry.security_model},#{entry.security_level},#{entry.context_match})"
        end
        parts << "view=#{@view_name}" if @view_name
        parts.join(" ")
      end
    end

    def initialize
      @contexts = {}
      @security_to_group = {}
      @access_entries = []
      @views = Hash.new { |hash, key| hash[key] = [] }
      add_context("")
    end

    ##
    # Add a context name to the vacmContextTable.  The default (empty)
    # context is always present.
    #
    def add_context(name)
      @contexts[name.to_str.dup] = true
    end

    def context?(name)
      @contexts.key?(name)
    end

    ##
    # Add a row to the vacmSecurityToGroupTable, mapping a security
    # model/name pair to a group.  Use security_model: :any to match
    # every security model.
    #
    def add_security_to_group(security_model:, security_name:, group_name:)
      key = [self.class.normalize_model(security_model), security_name.to_str.dup]
      @security_to_group[key] = group_name.to_str.dup
    end

    ##
    # Look up the group name for a security model/name pair.  Rows
    # configured with security_model :any act as a fallback.
    #
    def group_name_for(security_model:, security_name:)
      model = self.class.normalize_model(security_model)
      @security_to_group[[model, security_name.to_str]] ||
        @security_to_group[[ANY_MODEL, security_name.to_str]]
    end

    ##
    # Add a row to the vacmAccessTable.  The security level is the
    # minimum level a message must have to use this row.  context_match
    # is :exact (context name must equal context_prefix) or :prefix
    # (context name must begin with context_prefix).
    #
    def add_access(group_name:, security_model:, context_prefix: "",
                   security_level: :noAuthNoPriv, context_match: :exact,
                   read_view: nil, write_view: nil, notify_view: nil)
      context_match = context_match.to_sym
      unless [:exact, :prefix].include?(context_match)
        raise ArgumentError, "invalid context_match: #{context_match.inspect}"
      end
      entry = AccessEntry.new(
        group_name.to_str.dup,
        context_prefix.to_str.dup,
        self.class.normalize_model(security_model),
        self.class.normalize_level(security_level),
        context_match,
        read_view, write_view, notify_view
      )
      @access_entries << entry
      entry
    end

    ##
    # Add a row to the vacmViewTreeFamilyTable.  subtree may be an
    # ObjectId or a dotted string; mask is a binary string where each
    # bit (MSB first) says whether the corresponding subidentifier must
    # match (1) or is a wildcard (0).  A missing or short mask means
    # every subidentifier must match.  type is :included or :excluded.
    #
    def add_view_subtree(view_name, subtree, mask: nil, type: :included)
      type = type.to_sym
      unless [:included, :excluded].include?(type)
        raise ArgumentError, "invalid view subtree type: #{type.inspect}"
      end
      family = ViewSubtree.new(
        view_name.to_str.dup,
        subtree.is_a?(ObjectId) ? subtree : ObjectId.new(subtree),
        mask && mask.to_str.dup,
        type
      )
      @views[family.view_name] << family
      family
    end

    ##
    # Select the vacmAccessTable entry for the given group, context,
    # security model, and security level.  Among the matching rows, the
    # one with the highest security level wins; ties are broken by the
    # longest context prefix, then by configuration order.
    #
    def select_access_entry(group_name:, context_name:, security_model:,
                            security_level:)
      model = self.class.normalize_model(security_model)
      level = self.class.normalize_level(security_level)
      matches = @access_entries.select do |entry|
        entry.group_name == group_name &&
          (entry.security_model == model || entry.security_model == ANY_MODEL) &&
          entry.security_level <= level &&
          context_matches?(entry, context_name)
      end
      matches.max_by { |entry| [entry.security_level, entry.context_prefix.length] }
    end

    ##
    # Check whether an OID is inside a view.  Every view subtree whose
    # masked subidentifiers match the OID is a candidate; the candidate
    # with the longest subtree decides.  On equal-length ties an
    # :excluded row wins (fail-safe).
    #
    def view_includes?(view_name, oid)
      oid = ObjectId.new(oid) unless oid.is_a?(ObjectId)
      best = nil
      @views[view_name.to_str].each do |family|
        next unless subtree_matches?(family, oid)
        if best.nil? ||
           family.subtree.length > best.subtree.length ||
           (family.subtree.length == best.subtree.length && !family.included?)
          best = family
        end
      end
      best ? best.included? : false
    end

    ##
    # Full access check: resolve the group, select the access entry for
    # the operation, then test the OID against the selected view.
    # Returns an AccessDecision describing the outcome and the
    # configuration rows that were selected.
    #
    def decide(operation:, oid:, security_model:, security_name:,
               security_level: :noAuthNoPriv, context_name: "")
      params = {
        operation: operation,
        oid: oid,
        security_model: security_model,
        security_name: security_name,
        security_level: security_level,
        context_name: context_name
      }
      unless context?(context_name)
        return AccessDecision.new(:unknown_context, **params)
      end
      group = group_name_for(security_model: security_model,
                             security_name: security_name)
      unless group
        return AccessDecision.new(:unknown_security_name, **params)
      end
      entry = select_access_entry(group_name: group,
                                  context_name: context_name,
                                  security_model: security_model,
                                  security_level: security_level)
      unless entry
        return AccessDecision.new(:no_access_entry, group_name: group, **params)
      end
      view = entry.view_for(operation)
      if view.nil? || view.empty?
        return AccessDecision.new(:no_view_for_operation,
                                  group_name: group, access_entry: entry,
                                  **params)
      end
      unless view_includes?(view, oid)
        return AccessDecision.new(:not_in_view,
                                  group_name: group, access_entry: entry,
                                  view_name: view, **params)
      end
      AccessDecision.new(:ok, group_name: group, access_entry: entry,
                         view_name: view, **params)
    end

    class << self
      def normalize_level(level)
        return level.to_int if level.respond_to?(:to_int)
        code = SECURITY_LEVELS[level.to_sym]
        raise ArgumentError, "unknown security level: #{level.inspect}" unless code
        code
      end

      def normalize_model(model)
        return model.to_int if model.respond_to?(:to_int)
        code = SECURITY_MODELS[model.to_sym]
        raise ArgumentError, "unknown security model: #{model.inspect}" unless code
        code
      end
    end

    private

    def context_matches?(entry, context_name)
      case entry.context_match
      when :exact
        context_name == entry.context_prefix
      when :prefix
        context_name.start_with?(entry.context_prefix)
      end
    end

    def subtree_matches?(family, oid)
      family.subtree.each_with_index do |subid, index|
        next unless mask_bit?(family.mask, index)
        return false unless oid[index] == subid
      end
      true
    end

    def mask_bit?(mask, index)
      return true if mask.nil?
      byte = mask.getbyte(index / 8)
      return true if byte.nil? # short mask: trailing bits are 1 (must match)
      (byte & (0x80 >> (index % 8))) != 0
    end

  end

end
