# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  event["headers"] = event["headers"].transform_keys(&:downcase)
  if event['path'] == '/'
    if event['httpMethod'] == 'GET'
      if event["headers"].key?("authorization")
        token = event["headers"]["authorization"]
        begin
          decoded_token = JWT.decode token[7, token.length], ENV['JWT_SECRET'], 'HS256'
          data = decoded_token[0]
          return response(body: data["data"], status: 200)
        rescue JWT::ImmatureSignature
          return response(status: 401)
        rescue JWT::ExpiredSignature
          return response(status: 401)
        rescue JWT::DecodeError
          return response(status: 403)
        end 
      end
      return response(status: 403)
    else
      return response(status: 405)
    end
  elsif event['path'] == '/token'
    if event['httpMethod'] == 'POST'
      if event["headers"]["content-type"] == "application/json"
        begin
          payload = {
            data: JSON.parse(event['body']),
            exp: Time.now.to_i + 5,
            nbf: Time.now.to_i + 2,
          }
          token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
          return response(body: {:token => token}, status: 201)
        rescue Exception => e
          return response(status: 422)
        end
      else
        return response(status: 415)
      end
    else
      return response(status: 405)
    end
  else
    return response(status: 404)
  end
end


def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
