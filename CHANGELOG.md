# Change Log

## Unreleased:
* Added SNMP::VACM, a minimal View-based Access Control Model (RFC 3415)
  for the agent: access entries are selected by security name/model/level,
  context, and read/write/notify operation, and OIDs are checked against
  viewTreeFamily subtrees with masks
* Reworked SNMP::Agent with an ordered data tree and VACM enforcement;
  GETNEXT/GETBULK skip objects outside the requester's view instead of
  returning and removing them

## Changes for version 1.3.2:
* Accept non-standard error status codes

## Changes for version 1.3.1:
* Cleaned up deprecation warnings
* Fixed SNMP::Integer#<=> method for Ruby 2.3.0 and later
* Removed artificial limit on number of non-repeaters for GetBulkRequest
* SNMP::BER module no longer pollutes global namespace

## Changes for version 1.2.0:
* Removed support for Ruby 1.8
* Changed license to MIT License

## Changes for version 1.1.1:

* Incorporate various small pull requests

## Changes for version 1.1.0:

* Added MIB support to ObjectId and Varbind, so that to_s can return symbolic information
* Added to_str method to ObjectId to return a numeric OID string (old to_s behavior)
* TrapListener can now support multiple community strings

## Changes for version 1.0.4:

* New option handling and added lower-case versions of all options
* Added SNMP::VERSION constant
* Experimental support for IPv6
* Removed support for installation with setup.rb

## Changes for version 1.0.3:

* Minor changes to Manager class.  The :Transport option may now be an
  object or a class.  Explicity call Timeout.timeout so that a timeout
  method may be defined in subclasses.  Thanks to Eric Monti.

## Changes for version 1.0.2:

* Internal code changes to make this library compatible with both Ruby 1.8
  and Ruby 1.9.  Note that an ord() method is now added to the Fixnum class
  for Ruby 1.8.  See the ber.rb file for details.

## Changes for version 1.0.1:

* Made the host configurable for the TrapListener.  Previously defaulted
  to 'localhost'.

## Changes for version 1.0.0:

* Added to_s method to TimeTicks.  Displays time in human-readable form
  instead of just a number.  The to_i method can still be used to get the
  number of ticks.
