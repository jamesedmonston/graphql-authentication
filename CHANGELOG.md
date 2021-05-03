# GraphQL Authentication Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

## 1.9.0 - Unreleased

### Added

### Changed

- Improved checks for whether or not plugin should be injecting restrictions
- Reduced number of database calls when injecting unique user cache
- Removed `state` argument on Sign in with Apple mutations – this didn't work correctly with the iOS flow
- Removed unused `JWT` GraphQL type

### Fixed

- Fixed `Invalid Authorization Header` error on sites using Apache ([#52](https://github.com/jamesedmonston/graphql-authentication/issues/52) and [#53](https://github.com/jamesedmonston/graphql-authentication/issues/53) via [@GMConsultant](https://github.com/GMConsultant))

### Misc

- Added class method documentation blocks throughout plugin for easier third-party extensibility

## 1.8.0 - 2021-04-29

### Added

- Added `preferredLanguage` argument to `register` and `updateViewer` mutations ([#49](https://github.com/jamesedmonston/graphql-authentication/issues/49) via [@andrewfairlie](https://github.com/andrewfairlie))
- Added `username` arguments to `register` and `updateViewer` mutations. If username isn't set, it will fall back to the user's email address

### Changed

- `firstName` and `lastName` are now optional on the `register` mutation

### Fixed

- Fixed potential issue with queries against the public schema (PR [#48](https://github.com/jamesedmonston/graphql-authentication/pull/48) via [@tam](https://github.com/tam))
- Fixed error when sending a malformed JWT (PR [#48](https://github.com/jamesedmonston/graphql-authentication/pull/48) via [@tam](https://github.com/tam))
- Fixed potential error when visiting the plugin settings

## 1.7.0 - 2021-03-15

### Added

- Added `resendActivation` mutation for allowing users to resend an activation email ([#43](https://github.com/jamesedmonston/graphql-authentication/issues/43) via [@andrewfairlie](https://github.com/andrewfairlie))
- Added separate (customisable) response for unactivated users trying to authenticate ([#43](https://github.com/jamesedmonston/graphql-authentication/issues/43) via [@andrewfairlie](https://github.com/andrewfairlie))

### Fixed

- Fixed error that occurred when trying to clear expired tokens whilst using PostgreSQL ([#42](https://github.com/jamesedmonston/graphql-authentication/issues/42) via [@bartroelands](https://github.com/bartroelands))

## 1.6.1 - 2021-03-10

### Fixed

- Fixed issue where the `JWT Refresh Tokens` sidebar item was showing for non-admins (the page was never accessible, though!)

## 1.6.0 - 2021-03-10

### Added

- Added `activateUser` mutation for activating users who have received a Craft activation email ([#41](https://github.com/jamesedmonston/graphql-authentication/issues/41) via [@andrewfairlie](https://github.com/andrewfairlie) and [@magicspon](https://github.com/magicspon))

## 1.5.0 - 2021-02-24

### Added

- Added ability to set JWT Secret Key and Social app IDs/secrets via environment variables (thanks to [@dorineal](https://github.com/dorineal) for the pull request!)

## 1.4.4 - 2021-02-20

### Fixed

- Fixed issue with users not being activated through the `setPassword` mutation ([#38](https://github.com/jamesedmonston/graphql-authentication/issues/38) via [@magicspon](https://github.com/magicspon))

## 1.4.3 - 2021-02-11

### Fixed

- Fixed issue with tokens being removed before they had expired

## 1.4.2 - 2021-02-01

### Changed

- Improved performance of clearing expired tokens
- Removed deprecated `getUser` and `updateUser` – use `viewer` and `updateViewer` instead
- User types/fragments now need to be spread in authentication responses (see [here](https://github.com/jamesedmonston/graphql-authentication/issues/35#issuecomment-768528135))

### Fixed

- Fixed issue with entry/category/asset fields not saving on `register` or `updateViewer` mutations ([#35](https://github.com/jamesedmonston/graphql-authentication/issues/35) via [@howells](https://github.com/howells))
- Fixed compatibility issue with Craft 3.6.x ([#36](https://github.com/jamesedmonston/graphql-authentication/issues/36) via [@benrnorman](https://github.com/benrnorman))

## 1.4.1 - 2021-01-19

### Fixed

- Fixed issue with `refreshToken` mutation not always working in production environments

## 1.4.0 - 2020-12-30

### Added

- Added support for Sign in with Apple ([#14](https://github.com/jamesedmonston/graphql-authentication/issues/14))
- Added support for limiting user groups to Craft multi-site sites
- Added `viewer` query ([#30](https://github.com/jamesedmonston/graphql-authentication/commit/cc02b84ddbd2cc50c593082bbca3ca0773a6cd61) via [@tam](https://github.com/Tam))
- Added `updateViewer` mutation ([#30](https://github.com/jamesedmonston/graphql-authentication/commit/cc02b84ddbd2cc50c593082bbca3ca0773a6cd61) via [@tam](https://github.com/Tam))

### Changed

- Removed support for non-JWT tokens (note: **this is a breaking change**)
- Deprecated `getUser` query (this will be removed in a future release) ([#30](https://github.com/jamesedmonston/graphql-authentication/commit/cc02b84ddbd2cc50c593082bbca3ca0773a6cd61) via [@tam](https://github.com/Tam))
- Deprecated `updateUser` mutation (this will be removed in a future release) ([#30](https://github.com/jamesedmonston/graphql-authentication/commit/cc02b84ddbd2cc50c593082bbca3ca0773a6cd61) via [@tam](https://github.com/Tam))
- Improved error handling, production environments now return useful error messages and codes instead of `Internal server error` ([#31](https://github.com/jamesedmonston/graphql-authentication/issues/31) via [@tam](https://github.com/Tam))

### Fixed

- Fixed issue with `authorId` restrictions sometimes causing incorrect results to be returned ([#34](https://github.com/jamesedmonston/graphql-authentication/issues/34) via [@daltonrooney](https://github.com/daltonrooney))
- Fixed issue with users being able to assign themselves schemas, using social mutations (via [@daltonrooney](https://github.com/daltonrooney))

## 1.3.3 - 2020-12-10

### Changed

- `jwtExpiresAt` and `refreshTokenExpiresAt` are now returned in milliseconds to make JS validation simpler (this will always end in `000` as token expiry is stored in seconds in the database)

## 1.3.2 - 2020-12-08

### Fixed

- _Actually_ fix `Invalid Authorization Header` on queries/mutations against the public schema ([#23](https://github.com/jamesedmonston/graphql-authentication/issues/23) via [@approached](https://github.com/approached))
- Fix issue where tokens decoded from JWTs weren't being passed to the GraphQL API controller properly ([#28](https://github.com/jamesedmonston/graphql-authentication/issues/28) via [@daltonrooney](https://github.com/daltonrooney))

## 1.3.1 - 2020-12-07

### Fixed

- Ensure `isGraphiqlRequest` detects GraphiQL requests properly ([#23](https://github.com/jamesedmonston/graphql-authentication/issues/23) via [@approached](https://github.com/approached))

## 1.3.0 - 2020-12-06

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
