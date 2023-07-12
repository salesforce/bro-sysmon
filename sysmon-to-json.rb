#!/usr/bin/env ruby

require 'json'
require 'nokogiri'

def parse_xml(data)
  # Extract all comments: <!-- .* -->
  xml = Nokogiri::XML(data)
  comments = xml.xpath('//comment()').map { |x| x.content }
  # Accumulate sysmon event structure.
  events = {}
  ids = []
  comments.each do |comment|
    if comment.start_with?('SYSMON EVENT')
      match = comment.match(/ID (.+) : (.+) \[(.+)\]/)
      next unless match
      id, desc, name = match.to_a.drop(1)
      ids = id.split(' & ').map { |x| x.to_sym }
      ids.each do |id|
        events[id] = {
          name: name,
          desc: desc
        }
      end
    end
    if not ids.empty?
      if comment.start_with?('EVENT')
        id, details = comment.match(/EVENT (.+): "([^"]+)/).to_a.drop(1)
        next unless events.has_key?(id.to_sym)
        events[id.to_sym][:details] = details
      end
      if comment.start_with?('DATA')
        args = comment[/DATA: (.*)/, 1].split(', ')
        ids.each do |id|
          events[id][:args] = args
        end
      end
    end
  end
  return JSON[events]
end

if __FILE__ == $0
  puts parse_xml(STDIN.read)
end
