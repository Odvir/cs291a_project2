# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def valid_json?(string)
  !!(JSON.parse(string)) rescue false
end

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

  begin
    httpMethod = event['httpMethod']
    puts "hello"

    # get method
    if event['path'] == '/'
      if httpMethod != 'GET'
        return response(body: event, status: 405)
      end

      # Responds 403 if a proper Authorization: Bearer <TOKEN> header is not provided.
      # Responds 401 if either the token is not yet valid, or if it is expired.
      if !event.key?("headers")
        return response(body: nil, status: 403)
      end
      if !event["headers"].key?("Authorization")
        return response(body: nil, status: 403)
      end

      auth_array = event["headers"]["Authorization"].split(" ")
      if auth_array[0] != "Bearer"
        return response(body: nil, status: 403)
      end

      begin
        # add leeway to ensure the token is valid
        decoded_token = JWT.decode auth_array[1], ENV['JWT_SECRET'], true, {algorithm: 'HS256' }
      rescue JWT::ImmatureSignature => e
        return response(body: e, status: 401)
      rescue JWT::ExpiredSignature => e
        return response(body: e, status: 401)
      rescue JWT::DecodeError => e
        return response(body: e, status: 403)
      end
      
      decoded_value = decoded_token[0]['data']
      return response(body: decoded_value, status: 200)
    
    elsif event['path'] == '/auth/token'
      if httpMethod != 'POST'
        return response(body: event, status: 405)
      end

      # Responds 415 if the request content type is not application/json.
      # Responds 422 if the body of the request is not actually json.
      
      if event["body"] == nil
        return response(body: nil, status: 422)
      end

      if !valid_json?(event["body"])
        return response(body: nil, status: 422)
      end
      
      content = false
      event["headers"].each do |key, value|
        if key.downcase == 'content-type'
          content = true
          if value != 'application/json'
            return response(body: nil, status: 415)
          end
        end
      end

      if !content
        return response(status: 415)
      end
      
      jsonData = JSON.parse(event["body"])
      puts jsonData
      payload = {
        data: jsonData,
        exp: Time.now.to_i + 5,
        nbf: Time.now.to_i + 2
      }

      encoded_token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'

      return response(body: {"token": encoded_token}, status: 201)
    end
    
    return response(body: nil, status:404)
  rescue StandardError => e
    # Catch any uncaught errors and return a 500 response
    return response(body: { error: e.message }, status: 500)
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
               'path' => '/auth/token'
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