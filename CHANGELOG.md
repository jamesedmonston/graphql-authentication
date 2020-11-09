# GraphQL Authentication Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

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
