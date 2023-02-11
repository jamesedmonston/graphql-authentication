# GraphQL Authentication Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

## 2.3.1 - 2023-02-11

### Fixed

- Fixed issue with users sometimes being permanently granted Control Panel access ([#120](https://github.com/jamesedmonston/graphql-authentication/pull/120))
- Fixed issue with field permissions falling back to the public schema when passing `Bearer` tokens ([#119](https://github.com/jamesedmonston/graphql-authentication/pull/119))

## 2.3.0 - 2023-01-18

### Added

- Added 'magic link' authentication! To get started, enable it in your plugin settings and see [the docs](https://graphql-authentication.jamesedmonston.co.uk/usage/magic-authentication) ([#107](https://github.com/jamesedmonston/graphql-authentication/issues/107))

## 2.2.1 - 2023-01-10

### Fixed

- Fixed issue with settings breadcrumb being hardcoded to `/settings` ([#117](https://github.com/jamesedmonston/graphql-authentication/pull/117))

## 2.2.0 - 2023-01-07

### Added

- Added support for Microsoft OAuth sign in
- Added `deleteSocialAccount` mutation, for deleting password-less accounts. Throws an error if run on an account with a password ([#110](https://github.com/jamesedmonston/graphql-authentication/issues/110))

### Fixed

- Fixed issue with accounts not automatically activating ([#114](https://github.com/jamesedmonston/graphql-authentication/pull/114), thanks [@Stalex89](https://github.com/Stalex89)!)
- Fixed issue with plugin's field restrictions not applying to public schema ([#109](https://github.com/jamesedmonston/graphql-authentication/pull/109), thanks [@Zsavajji](https://github.com/Zsavajji)!)

## 2.1.2 - 2022-09-19

### Fixed

- Fixed issue with mutation field validation throwing an error ([#103](https://github.com/jamesedmonston/graphql-authentication/issues/103))
- Fixed issue with social registration not marking users as active if skip activation is enabled ([#100](https://github.com/jamesedmonston/graphql-authentication/issues/100))

## 2.1.1 - 2022-09-11

### Misc

- Ensure Twitter OAuth credentials are removed from session

## 2.1.0 - 2022-09-11

### Added

- Added setting to skip user activation when registering through social mutations ([#100](https://github.com/jamesedmonston/graphql-authentication/issues/100))

### Changed

- `firstName` and `lastName` have been migrated to `fullName` across all register and viewer mutations ([#101](https://github.com/jamesedmonston/graphql-authentication/issues/101))

### Fixed

- Fixed `updateViewer` mutation not updating user's name (use `fullName` parameter, as above) ([#101](https://github.com/jamesedmonston/graphql-authentication/issues/101))
- Fixed `deleteAccount` mutation not deleting user ([#102](https://github.com/jamesedmonston/graphql-authentication/issues/102))

## 2.0.0 - 2022-09-05

### Added

- Added Craft 4 support! ([#94](https://github.com/jamesedmonston/graphql-authentication/issues/94)) – huge thanks to Brandon Kelly for the PR!
- Added `deleteAccount` mutation ([#84](https://github.com/jamesedmonston/graphql-authentication/issues/84))

### Changed

- PHP >8.0 is now required
- Craft >4.0 is now required
- The email verification email is now sent out to users when updating their email via the `updateViewer` mutation ([#90](https://github.com/jamesedmonston/graphql-authentication/issues/90))
- When using the JWT returned from a `register` mutation to authenticate requests, all requests will throw a `Please activate your account` error until the account is activated ([#83](https://github.com/jamesedmonston/graphql-authentication/issues/83))

### Fixed

- When users register through a social mutation, they now receive an appropriate activation email (if enabled), rather than the set password email ([#72](https://github.com/jamesedmonston/graphql-authentication/issues/72))

## 1.12.3 - 2022-02-25

### Fixed

- Fixed issue with some custom fields breaking user registration mutations

## 1.12.2 - 2021-12-06

### Changed

- The password reset required flag is now respected. When a user with this flag set tries to authenticate, a password reset email is sent and an error message is returned ([#81](https://github.com/jamesedmonston/graphql-authentication/pull/81), thanks [@nstCactus](https://github.com/nstCactus)!)

### Fixed

- Fixed migration issue that occurred when setting a password for users with an unverified email (created in the control panel) ([#79](https://github.com/jamesedmonston/graphql-authentication/pull/79), thanks [@nstCactus](https://github.com/nstCactus)!)
- Fixed compatibility issue with Craft 3.7.24 ([#85](https://github.com/jamesedmonston/graphql-authentication/issues/85))
- Fixed issue with contextual error messages not being returned ([#74](https://github.com/jamesedmonston/graphql-authentication/issues/74))
- Fixed issue with field permissions not always being applied properly

## 1.12.1 - 2021-11-09

### Fixed

- Fixed migration issue that occurred when not using multiple schemas ([#78](https://github.com/jamesedmonston/graphql-authentication/issues/78))

## 1.12.0 - 2021-11-05

### Added

- A `TokenService::parseToken(string $jwt):Token` method that allows parsing a JWT from anywhere, not just the `Authorization` HTTP header ([#75](https://github.com/jamesedmonston/graphql-authentication/pull/75), thanks [@nstCactus](https://github.com/nstCactus)!)
- The ability to pass the token as a string to the `TokenService::getUserFromToken()` method instead of always getting the token from the `Authorization` HTTP header ([#75](https://github.com/jamesedmonston/graphql-authentication/pull/75), thanks [@nstCactus](https://github.com/nstCactus)!)

### Changed

- Tokens now store schema references via `schemaName` instead of `schemaId` to improve cross-environment behaviour ([#64](https://github.com/jamesedmonston/graphql-authentication/pull/64), thanks [@SayChi](https://github.com/SayChi)!)
- Creating new entries via a mutation no longer forces the author to be the current user, if an `authorId` argument is supplied (note: it still respects the `Restricted Entry Mutations` plugin settings!) ([#63](https://github.com/jamesedmonston/graphql-authentication/pull/63), thanks [@cliveportman](https://github.com/cliveportman)!)

### Fixed

- Fixed issue with user mutation fields not clearing value if sent as `null` ([#73](https://github.com/jamesedmonston/graphql-authentication/pull/73), thanks [@hendrik-agprop](https://github.com/hendrik-agprop)!)
- Fixed issue with users not being created as `pending` if 'suspend users by default' was enabled ([#77](https://github.com/jamesedmonston/graphql-authentication/pull/77), thanks [@Zsavajji](https://github.com/Zsavajji)!)
- Fixed issue with authentication mutations returning `Internal server error` instead of contextual errors ([#74](https://github.com/jamesedmonston/graphql-authentication/issues/74))

## 1.11.5 - 2021-09-27

### Fixed

- Fixed issue with errors being thrown as `Something went wrong when processing the GraphQL query.` instead of contextual errors. E.g. requests with an expired token will now throw `Invalid Authorization Header`

## 1.11.4 - 2021-09-23

### Fixed

- Fixed issue with `restrictForbiddenFields` throwing errors too eagerly ([#71](https://github.com/jamesedmonston/graphql-authentication/issues/71))
- Fixed issue with `globalSet` queries sometimes throwing an error ([#68](https://github.com/jamesedmonston/graphql-authentication/issues/68))

## 1.11.3 - 2021-08-27

### Fixed

- Fixed issue with lightswitch values not saving on `updateViewer` mutation

## 1.11.2 - 2021-08-20

### Fixed

- Fixed issue with requests sometimes falling back to public schema

## 1.11.1 - 2021-08-20

### Fixed

- Fixed issue with author-only restrictions sometimes not applying correctly

## 1.11.0 - 2021-08-14

### Added

- Added PHP 8 support (the required minimum PHP version is now 7.4)

### Changed

- User mutation fields are now typed correctly, allowing improved TypeScript codegen

### Fixed

- `preferredLanguage` field wasn't available on per user group `register` mutations
- `username` field wasn't available on per user group `register` mutations
- Fixed error when trying to save a `table` field on user mutations
- Fixed issue with site permissions not being enforced correctly per user group

## 1.10.3 - 2021-05-08

### Changed

- Expired refresh tokens are now hard deleted

### Fixed

- Fixed issue with schema scope not being retrieved from JWT correctly when restricting mutation arguments
- Ensured error codes are consistent when throwing invalid auth header errors

## 1.10.2 - 2021-05-07

### Fixed

- Fixed issue with schema injection not always resetting session correctly

## 1.10.1 – 2021-05-07

### Changed

- Improved field restriction logic and fallbacks

### Fixed

- Fixed issue with `refreshToken` mutation throwing an error ([#56](https://github.com/jamesedmonston/graphql-authentication/issues/56) via [@GMConsultant](https://github.com/GMConsultant))

## 1.10.0 - 2021-05-07

### Added

- Added support for granular (per schema) field permissions – it's now possible to disable fields from being updated via mutations; or being completely private to both mutations _and_ queries. See new `Fields` section in settings
- Added user avatar support – see new `photo` field on `updateViewer`, sending this argument as `null` will remove the avatar

## 1.9.1 - 2021-05-06

> {warning} **BREAKING**: This release migrates `deleteCurrentToken` and `deleteAllTokens` mutations to `deleteRefreshToken` and `deleteRefreshTokens`, respectively

### Changed

- Further improvements to performance by reducing the number of database calls and loops
- `deleteCurrentToken` and `deleteAllTokens` mutations have been migrated to `deleteRefreshToken` and `deleteRefreshTokens` – due to no longer storing Craft GraphQL tokens, there's no longer a need for a way of deleting them

### Fixed

- Fixed `updateViewer` mutation error ([#54](https://github.com/jamesedmonston/graphql-authentication/issues/54))
- Fixed mutations firing twice ([#55](https://github.com/jamesedmonston/graphql-authentication/issues/55) via [@tam](https://github.com/tam))
- Fixed plugin causing an error with console requests

## 1.9.0 - 2021-05-04

### Added

- Added separate `Service ID` and `Service Secret` fields for Sign in with Apple web implementations – if both native and web settings are populated, it is now necessary to pass a `platform` (`NATIVE`/`WEB`) argument to the `appleSignIn` mutation

### Changed

- The plugin no longer creates Craft GraphQL tokens – schemas encoded into JWTs are now directly passed into Craft's GraphQL controller! ([#29](https://github.com/jamesedmonston/graphql-authentication/issues/29) via [@approached](https://github.com/approached))
- Lots of under-the-hood improvements to improve performance by reducing the number of database calls
- Removed unused `JWT` GraphQL type

### Fixed

- Fixed `Invalid Authorization Header` error on sites using Apache ([#52](https://github.com/jamesedmonston/graphql-authentication/issues/52) and [#53](https://github.com/jamesedmonston/graphql-authentication/issues/53) via [@GMConsultant](https://github.com/GMConsultant))

### Misc

- Added class method documentation blocks throughout plugin for easier third-party extensibility
- All services are now available as static properties on the plugin instance, i.e. `GraphqlAuthentication::$tokenService`

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
