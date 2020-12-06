# GraphQL Authentication Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

## 1.3.0 - Unreleased

### Added

- Much improved [documentation](https://graphql-authentication.jamesedmonston.co.uk)!
- Added JWT and refresh token support ([#3](https://github.com/jamesedmonston/graphql-authentication/issues/3) thanks to [@timkelty](https://github.com/timkelty))
- Added support for Log in with Twitter
- Added support for Facebook login
- Added ability to customise response and error messages

### Changed

- Deprecated non-JWT tokens, these will be removed in version `1.4.0`. JWTs provide greater flexibility and security

### Fixed

- Fixed an issue where non-user tokens were being restricted ([#19](https://github.com/jamesedmonston/graphql-authentication/issues/21) via [@menberg](https://github.com/menberg))
- Fixed an issue where `family_name` might not be defined in Google Sign-In ([#25](https://github.com/jamesedmonston/graphql-authentication/issues/25) via [@daltonrooney](https://github.com/daltonrooney))
- Fixed an issue where the plugin settings screen would error if a deleted schema was assigned to a user group ([#26](https://github.com/jamesedmonston/graphql-authentication/issues/26) via [@daltonrooney](https://github.com/daltonrooney))

## 1.2.2 - 2020-12-01

### Fixed

- Fixed issue with `Auth` GQL type not registering properly in production mode

## 1.2.1 - 2020-12-01

### Fixed

- Fixed issue with requests against the public schema throwing `Invalid Authorization Header`

## 1.2.0 - 2020-11-26

### Added

- Added ability to disable user registration
- Added per user group schema assignment, user group assignment, and granular schema permissions (a `register` mutation is added for each group, if enabled)
- Added Google Sign-In support (adds a single `googleSignIn` mutation, or mutations per user group, depending on settings)
- Added `SameSite` cookie policy control
- Added unique, per user caching, to ensure users never see each other's cached queries
- Added a `schema` field to the authentication mutation responses

### Changed

- Reworked the plugins settings into a tabbed interface
- The `register` mutation now listens to the `requireEmailVerification` setting in user settings – creating users in a pending state, and sending an activation email
- Tokens are now created using `microtime()` instead of `time()` to avoid any name conflicts

### Fixed

- Fixed some deprecation errors

### Misc

- Lots of under-the-hood tidying to make maintenance a lot easier

## 1.1.8 - 2020-11-14

### Fixed

- Fixed issue with saving token expiry as 'never'

## 1.1.7 - 2020-11-13

### Fixed

- Fixed issue with trailing commas in function calls causing an error on environments running PHP <7.3

## 1.1.6 - 2020-11-11

### Fixed

- Fixed issue with `updatePassword` mutation failing validation
- Fixed issue with custom fields on users not setting correct values on `register` and `updateUser` mutations

## 1.1.5 - 2020-11-10

### Fixed

- Fixed issue with project config sync throwing `Calling unknown method: craft\console\Request::getBodyParam()`

## 1.1.4 - 2020-11-09

### Improved

- Improved `isGraphiqlRequest` detection

## 1.1.3 - 2020-11-09

### Fixed

- Fixed issues with non-user tokens throwing `Invalid Authorization Header`. Previously it was _always_ trying to validate queries against user permissions, but this was causing conflicts with tokens that will only be used server-side (i.e. in Next.js SSG requests)

## 1.1.2 - 2020-11-09

### Fixed

- Added empty fallback to `Craft::$app->getRequest()->getReferrer()`, to fix error if referrer is blank

## 1.1.1 - 2020-11-09

### Fixed

- Fixed issue with `isGraphiqlRequest` always returning `true`, breaking Craft's GraphiQL explorer

## 1.1.0 - 2020-11-04

### Added

- Added support for HTTP-Only cookie tokens, improving security (thanks [@timkelty](https://github.com/timkelty))

## 1.0.1 - 2020-11-03

### Added

- Update `lastLoginDate` on users when running `authenticate`/`register` mutations

## 1.0.0 - 2020-11-03

### Added

- Initial release
