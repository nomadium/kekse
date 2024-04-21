# frozen_string_literal: true

require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

require "standard/rake"

task default: %i[spec standard]

task :dev do
  system "PUBKEY=\"yrPIlkwBSd7u2J+r3QaVOpNHimigorfOOYKwHV6MihA=\" \
    rerun --ignore 'app/views/*' \"bundle exec rackup app/config.ru\""
end
