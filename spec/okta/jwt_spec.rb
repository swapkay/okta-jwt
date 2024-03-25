RSpec.describe Oktajwt::Jwt do

  issuer        = ENV["OKTA_ISSUER"]
  audience      = ENV["OKTA_AUDIENCE"]
  client_ids    = ENV["OKTA_CLIENT_IDS"].split(',') # [resource_owner_token, implicit_token, ...]
  client_secret = ENV["OKTA_CLIENT_SECRET"]

  Oktajwt::Jwt.configure! issuer: issuer, logger: Logger.new(STDOUT)

  auth_response = Oktajwt::Jwt.sign_in_user(
    username: 'test@example.org',
    password: 'Password123',
    client_id: client_ids.first,
    client_secret: client_secret,
    scope: 'openid profile')

  parsed_auth_response  = JSON.parse(auth_response.body)
  access_token          = parsed_auth_response['access_token']

  it "has a version number" do
    expect(Oktajwt::Jwt::VERSION).not_to be nil
  end

  it "fails if invalid issuer" do
    expect{Oktajwt::Jwt.verify_token(access_token,
      issuer:     'invalid',
      audience:   audience,
      client_id:  client_ids 
    )}.to raise_error(Oktajwt::Jwt::InvalidToken, 'Invalid issuer')
  end

  it "fails if invalid audience" do
    expect{Oktajwt::Jwt.verify_token(access_token,
      issuer:     issuer,
      audience:   'invalid',
      client_id:  client_ids 
    )}.to raise_error(Oktajwt::Jwt::InvalidToken, 'Invalid audience')
  end

  it "fails if invalid client" do
    expect{Oktajwt::Jwt.verify_token(access_token,
      issuer:     issuer,
      audience:   audience,
      client_id:  'invalid' 
    )}.to raise_error(Oktajwt::Jwt::InvalidToken, 'Invalid client')
  end

  it "fails if expired token" do
    header, payload, sig = access_token.split('.')
    decoded_payload = JSON.parse(Base64.decode64(payload))
    decoded_payload['exp'] = Time.now.to_i - 1000
    encoded_payload = Base64.strict_encode64(decoded_payload.to_json)
    expired_token = [header, encoded_payload, sig].join('.')

    expect{Oktajwt::Jwt.verify_token(expired_token,
      issuer:     issuer,
      audience:   audience,
      client_id:  client_ids 
    )}.to raise_error(Oktajwt::Jwt::InvalidToken, 'Token is expired')
  end

  it "does validate access_token" do
    Oktajwt::Jwt.logger = Logger.new(STDOUT)
    expect(Oktajwt::Jwt.verify_token(access_token,
      issuer:     issuer,
      audience:   audience,
      client_id:  client_ids
    )['exp']).to be_truthy
  end

  it "does have cached jwk" do
    expect(Oktajwt::Jwt::JWKS_CACHE.keys.size).to eq(1)
  end
end
