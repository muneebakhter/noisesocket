package helpers

import (
	"errors"

	"encoding/base64"

	"github.com/namsral/flag"
	"gopkg.in/noisesocket.v0"
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilapi"
)

func init() {
	flag.StringVar(&appPrivateKey, "appPrivateKey", "", "App private key base64")
	flag.StringVar(&appCardID, "appCardID", "", "App card id")
	flag.StringVar(&cardsServicePublicKey, "cardsServicePublicKey", "", "Card service public key base64")
	flag.StringVar(&cardServiceID, "cardServiceID", "", "Card service card ID")
	flag.StringVar(&token, "token", "", "Access token")
	flag.StringVar(&cardServiceUrl, "cardServiceUrl", "", "Card Service Url")
	flag.StringVar(&roCardServiceUrl, "roCardServiceUrl", "", "Ro Card Service Url")
	flag.StringVar(&identityServiceUrl, "identityServiceUrl", "", "Identity Service Url")
	flag.StringVar(&vraServiceUrl, "vraServiceUrl", "", "VRA Service Url")
}

var (
	appPrivateKey, appCardID, cardsServicePublicKey, cardServiceID, token,
	cardServiceUrl, roCardServiceUrl, identityServiceUrl, vraServiceUrl string
)

func Validate(api *virgilapi.Api) noisesocket.VerifyCallbackFunc {

	return func(publicKey []byte, fields []*noisesocket.Field) error {
		var sign, cert []byte

		for _, f := range fields {
			switch f.Type {
			case noisesocket.MessageTypeCustomCert:
				{
					cert = f.Data
					break
				}
			case noisesocket.MessageTypeSignature:
				{
					sign = f.Data
					break
				}

			}
		}

		if len(sign) == 0 || len(cert) == 0 {
			return errors.New("signature or certificate is missing")
		}

		card, err := api.Cards.Import(string(cert))
		if err != nil {
			return err
		}

		if res, err := card.Verify(publicKey, sign); !res || err != nil {
			return errors.New("key signature valdation failed")
		}
		return nil
	}
}

func GetApi() *virgilapi.Api {

	decodedKey, _ := base64.StdEncoding.DecodeString(appPrivateKey)
	decodedServicePub, _ := base64.StdEncoding.DecodeString(cardsServicePublicKey)
	appkey, _ := virgil.Crypto().ImportPrivateKey(decodedKey, "")

	pub, _ := appkey.ExtractPublicKey()
	appPub, _ := pub.Encode()

	api, err := virgilapi.NewWithConfig(virgilapi.Config{
		Token: token,
		ClientParams: &virgilapi.ClientParams{

			CardServiceURL:         cardServiceUrl,
			ReadOnlyCardServiceURL: roCardServiceUrl,
			IdentityServiceURL:     identityServiceUrl,
			VRAServiceURL:          vraServiceUrl,
		},
		Credentials: &virgilapi.AppCredentials{
			AppId:      appCardID,
			PrivateKey: decodedKey,
		},
		CardVerifiers: map[string]virgilapi.Buffer{
			cardServiceID: decodedServicePub,
			appCardID:     appPub,
		},
		SkipBuiltInVerifiers: true,
	})

	if err != nil {
		panic(err)
	}
	return api
}

func MakePayload(instancePublic []byte, card *virgilapi.Card, key *virgilapi.Key) []*noisesocket.Field {
	sign, err := key.Sign(instancePublic)

	if err != nil {
		panic(err)
	}

	exportedCard, err := card.Export()
	if err != nil {
		panic(err)
	}

	return []*noisesocket.Field{
		{
			Type: noisesocket.MessageTypeSignature,
			Data: sign,
		},
		{
			Type: noisesocket.MessageTypeCustomCert,
			Data: []byte(exportedCard),
		},
	}
}

func GenerateAppSignedCard(api *virgilapi.Api) (*virgilapi.Card, *virgilapi.Key) {

	serverCardKey, err := api.Keys.Generate()

	if err != nil {
		panic(err)
	}

	serverCard, err := api.Cards.Create("http server", serverCardKey, map[string]string{
		"os": "windows",
	})

	serverCard, err = api.Cards.Publish(serverCard)
	if err != nil {

		panic(err)
	}
	return serverCard, serverCardKey
}
