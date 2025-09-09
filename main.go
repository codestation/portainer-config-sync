package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/goccy/go-yaml"
	portainer "github.com/portainer/client-api-go/v2/pkg/client"
	"github.com/portainer/client-api-go/v2/pkg/client/auth"
	"github.com/portainer/client-api-go/v2/pkg/client/endpoint_groups"
	"github.com/portainer/client-api-go/v2/pkg/client/endpoints"
	"github.com/portainer/client-api-go/v2/pkg/client/settings"
	"github.com/portainer/client-api-go/v2/pkg/client/team_memberships"
	"github.com/portainer/client-api-go/v2/pkg/client/teams"
	"github.com/portainer/client-api-go/v2/pkg/client/users"
	"github.com/portainer/client-api-go/v2/pkg/models"
)

const PageSize = int64(100)

type PortainerConfig struct {
	URL              string            `yaml:"url"`
	Auth             Auth              `yaml:"auth"`
	Teams            []string          `yaml:"teams"`
	Users            []User            `yaml:"users"`
	Endpoints        []Endpoint        `yaml:"endpoints"`
	EndpointGroups   []EndpointGroup   `yaml:"endpointGroups"`
	ResourceControls []ResourceControl `yaml:"resourceControls"`
	OIDC             *OIDC             `yaml:"oidc"`
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type User struct {
	Name  string     `yaml:"name"`
	Admin bool       `yaml:"admin"`
	Teams []UserTeam `yaml:"teams"`
}

type UserTeam struct {
	Name string `yaml:"name"`
	Role string `yaml:"role"` // "leader" or "member"
}

type Endpoint struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"` // "kubernetes" or "docker"
	URL   string `yaml:"url"`
	Group string `yaml:"group"`
}

type EndpointGroup struct {
	Name           string         `yaml:"name"`
	Description    string         `yaml:"description"`
	AccessPolicies []AccessPolicy `yaml:"accessPolicies"`
}

type ResourceControl struct {
	Service   string   `yaml:"service"`
	Endpoint  string   `yaml:"endpoint"`
	Public    bool     `yaml:"public"`
	AdminOnly bool     `yaml:"adminOnly"`
	Teams     []string `yaml:"teamAccesses"`
	Users     []string `yaml:"userAccesses"`
}

type AccessPolicy struct {
	Team string `yaml:"team"`
	Role string `yaml:"role"` // "standard-user"
}

type OIDC struct {
	ClientID         string   `yaml:"clientID"`
	ClientSecret     string   `yaml:"clientSecret"`
	Scopes           []string `yaml:"scopes"`
	UserIdentifier   string   `yaml:"userIdentifier"`
	AccessTokenURI   string   `yaml:"accessTokenURI"`
	AuthorizationURI string   `yaml:"authorizationURI"`
	ResourceURI      string   `yaml:"resourceURI"`
	LogoutURI        string   `yaml:"logoutURI"`
	RedirectURI      string   `yaml:"redirectURI"`
	DefaultTeam      string   `yaml:"defaultTeam"`
}

type PortainerClient struct {
	Client *portainer.PortainerClientAPI
	Auth   runtime.ClientAuthInfoWriter
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	slog.Info("Loading configuration file", "path", configPath)
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		slog.Error("Failed to read config", "error", err)
		os.Exit(1)
	}

	var cfg PortainerConfig
	if err := yaml.Unmarshal(configFile, &cfg); err != nil {
		slog.Error("Failed to unmarshal config", "error", err)
		os.Exit(1)
	}

	portainerPassword := os.Getenv("PORTAINER_ADMIN_PASSWORD")
	if portainerPassword != "" {
		slog.Info("Using password from environment variable")
		cfg.Auth.Password = portainerPassword
	}

	slog.Info("Starting Portainer initialization")

	portainerURL, err := url.Parse(cfg.URL)
	if err != nil {
		slog.Error("Failed to parse URL", "url", cfg.URL, "error", err)
		os.Exit(1)
	}

	pClient := portainer.NewHTTPClientWithConfig(strfmt.Default, &portainer.TransportConfig{
		Host:     portainerURL.Host,
		BasePath: portainer.DefaultBasePath,
		Schemes:  []string{portainerURL.Scheme},
	})

	authParams := auth.NewAuthenticateUserParams().WithBody(&models.AuthAuthenticatePayload{
		Username: &cfg.Auth.Username,
		Password: &cfg.Auth.Password,
	})

	authResponse, err := pClient.Auth.AuthenticateUser(authParams)
	if err != nil {
		slog.Error("Error authenticating with Portainer", "error", err)
		os.Exit(1)
	}

	bearerAuth := runtime.ClientAuthInfoWriterFunc(func(r runtime.ClientRequest, _ strfmt.Registry) error {
		return r.SetHeaderParam("Authorization", "Bearer "+authResponse.Payload.Jwt)
	})

	pc := &PortainerClient{
		Client: pClient,
		Auth:   bearerAuth,
	}

	ctx := context.Background()

	for _, team := range cfg.Teams {
		_, err := pc.SyncTeam(ctx, team)
		if err != nil {
			slog.Error("Error syncing team", "team", team, "error", err)
			os.Exit(1)
		}
	}

	// Add admins and users to the team
	slog.Info("Processing users from config")
	for _, user := range cfg.Users {
		if err := pc.SyncUser(ctx, &user); err != nil { // Role 1: Team Leader
			slog.Error("Error syncing user", "username", user.Name, "error", err)
			os.Exit(1)
		}
	}

	for _, group := range cfg.EndpointGroups {
		err := pc.SyncEndpointGroup(ctx, group)
		if err != nil {
			slog.Error("Error syncing endpoint group", "name", group.Name, "error", err)
			os.Exit(1)
		}
	}

	for _, endpoint := range cfg.Endpoints {
		if err := pc.SyncEndpoint(ctx, &endpoint); err != nil {
			slog.Error("Error syncing endpoint", "endpoint", endpoint.Name, "error", err)
			os.Exit(1)
		}
	}

	if cfg.OIDC != nil {
		oidcClientSecret := os.Getenv("OIDC_CLIENT_SECRET")
		if oidcClientSecret != "" {
			slog.Info("Using OIDC client secret from environment variable")
			cfg.OIDC.ClientSecret = oidcClientSecret
		}

		// Ensure OIDC is configured
		if err := pc.SyncOIDC(ctx, cfg.OIDC); err != nil {
			slog.Error("Error syncing OIDC configuration", "error", err)
			os.Exit(1)
		}
	}

	slog.Info("Portainer initialization completed successfully.")
}

func (pc *PortainerClient) SyncTeam(ctx context.Context, teamName string) (*models.PortainerTeam, error) {
	slog.Info("Ensuring team exists", "team", teamName)
	params := teams.NewTeamListParams()
	teamResponse, err := pc.Client.Teams.TeamList(params.WithContext(ctx), pc.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to list teams: %w", err)
	}

	for _, team := range teamResponse.Payload {
		if team.Name == teamName {
			slog.Info("Team already exists", "team", teamName, "id", team.ID)
			return team, nil
		}
	}

	slog.Info("Team not found, creating it", "team", teamName)
	createParams := teams.NewTeamCreateParams().WithBody(&models.TeamsTeamCreatePayload{
		Name: &teamName,
	})
	newTeamResponse, err := pc.Client.Teams.TeamCreate(createParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create team '%s': %w", teamName, err)
	}
	slog.Info("Team created", "team", teamName, "id", newTeamResponse.Payload.ID)
	return newTeamResponse.Payload, nil
}

func (pc *PortainerClient) SyncUser(ctx context.Context, userConfig *User) error {
	slog.Info("Syncing user", "user", userConfig.Name)

	userListParams := users.NewUserListParams()
	userList, err := pc.Client.Users.UserList(userListParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	username := userConfig.Name

	userIndex := slices.IndexFunc(userList.Payload, func(user *models.PortainereeUser) bool {
		return user.Username == username
	})

	var currentUser *models.PortainereeUser

	if userIndex != -1 {
		currentUser = userList.Payload[userIndex]
	}

	// Create user if not found
	if currentUser == nil {
		slog.Info("User not found, creating it", "username", username)

		randomBytes := make([]byte, 16)
		_, err := rand.Read(randomBytes)
		if err != nil {
			return fmt.Errorf("failed to generate random password for user '%s': %w", username, err)
		}

		randomPassword := hex.EncodeToString(randomBytes)

		var role int64
		if userConfig.Admin {
			role = 1 // Admin
		} else {
			role = 2 // Standard user
		}
		createUserParams := users.NewUserCreateParams().WithBody(&models.UsersUserCreatePayload{
			Username: &username,
			Password: &randomPassword,
			Role:     &role,
		})
		userResponse, err := pc.Client.Users.UserCreate(createUserParams.WithContext(ctx), pc.Auth)
		if err != nil {
			return fmt.Errorf("failed to create user '%s': %w", username, err)
		}

		currentUser = userResponse.Payload
		slog.Info("User created", "username", currentUser.Username, "id", currentUser.ID)
	} else {
		slog.Info("User already exists", "username", username, "id", currentUser.ID)
	}

	teamListParams := teams.NewTeamListParams()
	teamsResult, err := pc.Client.Teams.TeamList(teamListParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to list teams: %w", err)
	}

	userTeams := teamsResult.Payload

	teamMembershipParams := team_memberships.NewTeamMembershipListParams()
	teamMembershipResult, err := pc.Client.TeamMemberships.TeamMembershipList(teamMembershipParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to list team memberships: %w", err)
	}

	teamMemberships := teamMembershipResult.Payload

	// Sync team memberships
	for _, teamConfig := range userConfig.Teams {
		teamIndex := slices.IndexFunc(userTeams, func(team *models.PortainerTeam) bool {
			return team.Name == teamConfig.Name
		})

		if teamIndex == -1 {
			return fmt.Errorf("team '%s' not found for user '%s' assignment", teamConfig.Name, username)
		}

		team := userTeams[teamIndex]

		membershipIndex := slices.IndexFunc(teamMemberships, func(membership *models.PortainerTeamMembership) bool {
			return membership.UserID == currentUser.ID && membership.TeamID == team.ID
		})

		var membership *models.PortainerTeamMembership

		if membershipIndex != -1 {
			membership = teamMembershipResult.Payload[membershipIndex]
		}

		var teamRole int64
		if teamConfig.Role == "leader" {
			teamRole = 1 // Team Leader
		} else {
			teamRole = 2 // Team Member
		}

		if membership == nil {
			slog.Info("User is not a member of team, adding", "username", username, "team", teamConfig.Name)

			createTeamMembershipParams := team_memberships.NewTeamMembershipCreateParams().
				WithBody(&models.TeammembershipsTeamMembershipCreatePayload{
					UserID: &currentUser.ID,
					TeamID: &team.ID,
					Role:   &teamRole,
				})

			_, err = pc.Client.TeamMemberships.TeamMembershipCreate(createTeamMembershipParams.WithContext(ctx), pc.Auth)
			if err != nil {
				return fmt.Errorf("failed to create team membership: %w", err)
			}

			continue
		}

		if membership.Role == teamRole {
			slog.Info("User's team role is already up to date", "user", username, "team", teamConfig.Name, "role", teamConfig.Role)
			continue
		}

		slog.Info("Updating user's team role", "user", username, "team", teamConfig.Name, "role", teamConfig.Role)

		updateTeamMembershipParams := team_memberships.NewTeamMembershipUpdateParams().
			WithID(membership.ID).
			WithBody(&models.TeammembershipsTeamMembershipUpdatePayload{
				UserID: &currentUser.ID,
				TeamID: &team.ID,
				Role:   &teamRole,
			})

		_, err = pc.Client.TeamMemberships.TeamMembershipUpdate(updateTeamMembershipParams.WithContext(ctx), pc.Auth)
		if err != nil {
			return fmt.Errorf("failed to update team membership: %w", err)
		}

		slog.Info("User's team role updated", "user", username, "team", teamConfig.Name, "role", teamConfig.Role)
	}

	return nil
}

func (pc *PortainerClient) SyncOIDC(ctx context.Context, oidcCfg *OIDC) error {
	slog.Info("Ensuring OIDC authentication is configured")

	settingsInspectParams := settings.NewSettingsInspectParams()
	currentSettings, err := pc.Client.Settings.SettingsInspect(settingsInspectParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to get current settings: %w", err)
	}

	var team *models.PortainerTeam

	if oidcCfg.DefaultTeam != "" {
		teamListParams := teams.NewTeamListParams()
		teamsResult, err := pc.Client.Teams.TeamList(teamListParams.WithContext(ctx), pc.Auth)
		if err != nil {
			return fmt.Errorf("failed to list teams: %w", err)
		}

		teamIndex := slices.IndexFunc(teamsResult.Payload, func(t *models.PortainerTeam) bool {
			return t.Name == oidcCfg.DefaultTeam
		})

		if teamIndex != -1 {
			team = teamsResult.Payload[teamIndex]
		} else {
			return fmt.Errorf("default team '%s' not found for OIDC configuration", oidcCfg.DefaultTeam)
		}
	}

	// check that all oauth settings are synced, if they are, do nothing
	if currentSettings.Payload.AuthenticationMethod == 3 &&
		currentSettings.Payload.OAuthSettings.ClientID == oidcCfg.ClientID &&
		currentSettings.Payload.OAuthSettings.ClientSecret == oidcCfg.ClientSecret &&
		currentSettings.Payload.OAuthSettings.AccessTokenURI == oidcCfg.AccessTokenURI &&
		currentSettings.Payload.OAuthSettings.AuthorizationURI == oidcCfg.AuthorizationURI &&
		currentSettings.Payload.OAuthSettings.ResourceURI == oidcCfg.ResourceURI &&
		currentSettings.Payload.OAuthSettings.RedirectURI == oidcCfg.RedirectURI &&
		currentSettings.Payload.OAuthSettings.LogoutURI == oidcCfg.LogoutURI &&
		currentSettings.Payload.OAuthSettings.UserIdentifier == oidcCfg.UserIdentifier &&
		currentSettings.Payload.OAuthSettings.Scopes == strings.Join(oidcCfg.Scopes, " ") &&
		currentSettings.Payload.OAuthSettings.SSO &&
		(oidcCfg.DefaultTeam == "" || (team != nil && currentSettings.Payload.OAuthSettings.DefaultTeamID == team.ID)) {
		slog.Info("OIDC settings are already synced. Skipping update.")
		return nil
	}

	updateParams := settings.NewSettingsUpdateParams().WithBody(&models.SettingsSettingsUpdatePayload{
		AuthenticationMethod: 3, // OIDC
		OauthSettings: &models.PortainereeOAuthSettings{
			ClientID:         oidcCfg.ClientID,
			ClientSecret:     oidcCfg.ClientSecret,
			AccessTokenURI:   oidcCfg.AccessTokenURI,
			AuthorizationURI: oidcCfg.AuthorizationURI,
			ResourceURI:      oidcCfg.ResourceURI,
			RedirectURI:      oidcCfg.RedirectURI,
			LogoutURI:        oidcCfg.LogoutURI,
			UserIdentifier:   oidcCfg.UserIdentifier,
			Scopes:           strings.Join(oidcCfg.Scopes, " "),
			SSO:              true,
		},
	})

	if team != nil {
		updateParams.Body.OauthSettings.DefaultTeamID = team.ID
	}

	_, err = pc.Client.Settings.SettingsUpdate(updateParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to update settings for OIDC: %w", err)
	}

	slog.Info("OIDC authentication configured successfully.")
	return nil
}

func (pc *PortainerClient) SyncEndpointGroup(ctx context.Context, endpointGroup EndpointGroup) error {
	slog.Info("Ensuring endpoint group exists", "group", endpointGroup.Name)
	endpointGroupListParams := endpoint_groups.NewEndpointGroupListParams()
	groupResponse, err := pc.Client.EndpointGroups.EndpointGroupList(endpointGroupListParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to list endpoint groups: %w", err)
	}

	endpointGroupIndex := slices.IndexFunc(groupResponse.Payload, func(eg *models.PortainerEndpointGroup) bool {
		return eg.Name == endpointGroup.Name
	})

	var newEndpointGroup *models.PortainerEndpointGroup

	if endpointGroupIndex != -1 {
		newEndpointGroup = groupResponse.Payload[endpointGroupIndex]
	}

	if newEndpointGroup == nil {
		slog.Info("Endpoint group not found, creating it", "group", endpointGroup.Name)
		createParams := endpoint_groups.NewPostEndpointGroupsParams().WithBody(&models.EndpointgroupsEndpointGroupCreatePayload{
			Name:        &endpointGroup.Name,
			Description: endpointGroup.Description,
		})

		createdGroup, err := pc.Client.EndpointGroups.PostEndpointGroups(createParams.WithContext(ctx), pc.Auth)
		if err != nil {
			return fmt.Errorf("failed to create endpoint group '%s': %w", endpointGroup.Name, err)
		}

		newEndpointGroup = createdGroup.Payload
		slog.Info("Endpoint group created", "group", newEndpointGroup.Name, "id", newEndpointGroup.ID)
	} else {
		slog.Info("Endpoint group already exists", "group", newEndpointGroup.Name, "id", newEndpointGroup.ID)

		// check if description is different
		if newEndpointGroup.Description != endpointGroup.Description {
			slog.Info("Endpoint group description differs, updating it", "group", newEndpointGroup.Name)

			updateParams := endpoint_groups.NewEndpointGroupUpdateParams().WithID(newEndpointGroup.ID).
				WithBody(&models.EndpointgroupsEndpointGroupUpdatePayload{
					Description: endpointGroup.Description,
				})

			_, err := pc.Client.EndpointGroups.EndpointGroupUpdate(updateParams.WithContext(ctx), pc.Auth)
			if err != nil {
				return fmt.Errorf("failed to update endpoint group '%s': %w", newEndpointGroup.Name, err)
			}

			slog.Info("Endpoint group updated", "group", newEndpointGroup.Name)
		} else {
			slog.Info("Endpoint group is up to date", "group", newEndpointGroup.Name)
		}
	}

	params := teams.NewTeamListParams()
	teamResponse, err := pc.Client.Teams.TeamList(params.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to list teams: %w", err)
	}

	userTeams := teamResponse.Payload

	for _, accessPolicy := range endpointGroup.AccessPolicies {
		teamIndex := slices.IndexFunc(userTeams, func(team *models.PortainerTeam) bool {
			return team.Name == accessPolicy.Team
		})

		if teamIndex == -1 {
			return fmt.Errorf("team '%s' not found for endpoint group '%s' access policy", accessPolicy.Team, endpointGroup.Name)
		}

		team := userTeams[teamIndex]

		teamIdStr := strconv.FormatInt(team.ID, 10)

		var roleId int64
		switch accessPolicy.Role {
		case "standard-user":
			roleId = 0 // Standard user
		default:
			return fmt.Errorf("unknown access policy role '%s' for team '%s' in endpoint group '%s'", accessPolicy.Role, accessPolicy.Team, endpointGroup.Name)
		}

		if _, ok := newEndpointGroup.TeamAccessPolicies[teamIdStr]; !ok {
			endpointGroupUpdateParams := endpoint_groups.NewEndpointGroupUpdateParams().WithID(newEndpointGroup.ID).
				WithBody(&models.EndpointgroupsEndpointGroupUpdatePayload{
					TeamAccessPolicies: map[string]models.PortainerAccessPolicy{
						teamIdStr: {RoleID: roleId},
					},
				})
			_, err = pc.Client.EndpointGroups.EndpointGroupUpdate(endpointGroupUpdateParams.WithContext(ctx), pc.Auth)
			if err != nil {
				return fmt.Errorf("failed to update endpoint group '%s': %w", newEndpointGroup.Name, err)
			}
		}
	}

	return nil
}

func (pc *PortainerClient) SyncEndpoint(ctx context.Context, endpoint *Endpoint) error {
	slog.Info("Ensuring endpoint exists", "endpoint", endpoint.Name)

	start := int64(1)
	limit := PageSize
	var newEndpoint *models.PortainereeEndpoint

	for {
		endpointListParams := endpoints.NewEndpointListParams().WithStart(&start).WithLimit(&limit)
		endpointListResult, err := pc.Client.Endpoints.EndpointList(endpointListParams.WithContext(ctx), pc.Auth)
		if err != nil {
			return fmt.Errorf("failed to list endpoints: %w", err)
		}

		endpointListLen := len(endpointListResult.Payload)
		if endpointListLen == 0 {
			break
		}

		endpointIndex := slices.IndexFunc(endpointListResult.Payload, func(e *models.PortainereeEndpoint) bool {
			return e.Name == endpoint.Name
		})

		if endpointIndex != -1 {
			newEndpoint = endpointListResult.Payload[endpointIndex]
			break
		}

		start += int64(endpointListLen)
	}

	var endpointGroup *models.PortainerEndpointGroup

	endpointGroupListParams := endpoint_groups.NewEndpointGroupListParams()
	endpointGroupResult, err := pc.Client.EndpointGroups.EndpointGroupList(endpointGroupListParams.WithContext(ctx), pc.Auth)
	if err != nil {
		return fmt.Errorf("failed to list endpoint groups: %w", err)
	}

	endpointGroupIndex := slices.IndexFunc(endpointGroupResult.Payload, func(group *models.PortainerEndpointGroup) bool {
		return group.Name == endpoint.Group
	})

	if endpointGroupIndex != -1 {
		endpointGroup = endpointGroupResult.Payload[endpointGroupIndex]
	}

	if newEndpoint == nil {
		slog.Info("Endpoint not found, will be created", "endpoint", endpoint.Name)

		var endpointType int64

		switch endpoint.Type {
		case "kubernetes":
			endpointType = 5
		case "docker":
			endpointType = 2
		default:
			return fmt.Errorf("unknown endpoint type '%s' for endpoint '%s'", endpoint.Type, endpoint.Name)
		}

		tls := true
		createParams := endpoints.NewEndpointCreateParams().
			WithName(endpoint.Name).
			WithEndpointCreationType(endpointType).
			WithURL(&endpoint.URL).
			WithTLS(&tls).
			WithTLSSkipVerify(&tls).
			WithTLSSkipClientVerify(&tls)

		if endpointGroup != nil {
			createParams = createParams.WithGroupID(&endpointGroup.ID)
		}

		endpointResult, err := pc.Client.Endpoints.EndpointCreate(createParams.WithContext(ctx), pc.Auth)
		if err != nil {
			return fmt.Errorf("failed to create endpoint: %w", err)
		}

		newEndpoint = endpointResult.Payload
		slog.Info("Endpoint created", "endpoint", newEndpoint.Name, "id", newEndpoint.ID)
	} else {
		// check if endpoint is changed
		if newEndpoint.URL != endpoint.URL || (endpointGroup != nil && newEndpoint.GroupID != endpointGroup.ID) {
			slog.Info("Endpoint configuration differs, will be updated", "endpoint", newEndpoint.Name)

			updateParams := endpoints.NewEndpointUpdateParams().WithID(newEndpoint.ID).
				WithBody(&models.EndpointsEndpointUpdatePayload{
					URL: endpoint.URL,
				})

			if endpointGroup != nil {
				updateParams.Body.GroupID = endpointGroup.ID
			}

			if _, err := pc.Client.Endpoints.EndpointUpdate(updateParams.WithContext(ctx), pc.Auth); err != nil {
				return fmt.Errorf("failed to update endpoint '%s': %w", newEndpoint.Name, err)
			}
		} else {
			slog.Info("Endpoint configuration is up to date", "endpoint", newEndpoint.Name)
		}
	}

	return nil
}
