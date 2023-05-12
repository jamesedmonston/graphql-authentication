# GraphQL Authentication plugin for Craft CMS 3.5+

GraphQL Authentication adds a JWT authentication layer to your Craft CMS GraphQL endpoint.

## Plugin Overview

- Adds support for user registration and authentication (see [Authentication](https://graphql-authentication.jamesedmonston.co.uk/usage/authentication))
- Adds support for 'magic link' authentication (see [Authentication](https://graphql-authentication.jamesedmonston.co.uk/usage/authentication))
- Adds support for social sign-in – currently Google, Facebook, Twitter, Apple, and Microsoft (see [Social](https://graphql-authentication.jamesedmonston.co.uk/usage/social))
- Adds ability to define per-section user restrictions (queries and mutations can be limited to author-only) (see [User Settings](https://graphql-authentication.jamesedmonston.co.uk/settings/users))
- Checks mutation fields against schema permissions, and prevents fields being saved if user is trying to access private entries/assets
- Adds ability to assign unique schemas for each user group
- Adds ability to restrict user queries and mutations to Craft multi-site sites
- Adds ability to mark fields as private – stopping users from querying/mutating fields on entries
- Adds a unique, per-user query cache

## Documentation

You can view the documention for the plugin [here](https://graphql-authentication.jamesedmonston.co.uk).
