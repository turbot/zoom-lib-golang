package zoom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	cache "github.com/Code-Hex/go-generics-cache"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func OAuthToken(accountID string, clientID string, clientSecret string) (string, error) {
	// set the cache key
	cacheKey := accountID + clientID + clientSecret

	if token, ok := oauthCache.Get(cacheKey); ok {
		fmt.Println("cache hit")
		return token, nil
	}

	data := url.Values{}
	data.Set("grant_type", "account_credentials")
	data.Set("account_id", accountID)

	req, err := http.NewRequest("POST", "https://zoom.us/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	credentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credentials))
	req.Header.Set("Host", "zoom.us")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	var accessTokenResp AccessTokenResponse
	err = json.Unmarshal(body, &accessTokenResp)
	if err != nil {
		return "", err
	}
	fmt.Println("First time/Expired token")
	// set the expiration time for the token to be 5 minutes less than the actual expiry time
	expirationTime := time.Duration(accessTokenResp.ExpiresIn-3553) * time.Second

	oauthCache.Set(cacheKey, accessTokenResp.AccessToken, cache.WithExpiration(expirationTime))

	return accessTokenResp.AccessToken, nil
}
