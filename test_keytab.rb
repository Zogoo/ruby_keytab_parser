require './keytab.rb'
require 'byebug'

file = File.binread('./keytab.kt')

kt = KeyTab.new(file)

raise 'Could not parse keytab entries' if kt.key_tab_entries.empty?