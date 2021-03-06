module Octokit
  class Client

    # Methods for the Users API
    #
    # @see https://developer.github.com/v3/users/
    module Users

      # List all GitHub users
      #
      # This provides a list of every user, in the order that they signed up
      # for GitHub.
      #
      # @param options [Hash] Optional options.
      # @option options [Integer] :since The integer ID of the last User that
      #   you’ve seen.
      #
      # @see https://developer.github.com/v3/users/#get-all-users
      #
      # @return [Array<Sawyer::Resource>] List of GitHub users.
      def all_users(options = {})
        paginate "users", options
      end

      # Get a single user
      #
      # @param user [Integer, String] GitHub user login or id.
      # @return [Sawyer::Resource]
      # @see https://developer.github.com/v3/users/#get-a-single-user
      # @see https://developer.github.com/v3/users/#get-the-authenticated-user
      # @example
      #   Octokit.user("sferik")
      def user(user=nil, options = {})
        get User.path(user), options
      end

      # Retrieve the access_token.
      #
      # @param code [String] Authorization code generated by GitHub.
      # @param app_id [String] Client Id we received when our application was registered with GitHub. Defaults to client_id.
      # @param app_secret [String] Client Secret we received when our application was registered with GitHub. Defaults to client_secret.
      # @return [Sawyer::Resource] Hash holding the access token.
      # @see https://developer.github.com/v3/oauth/#web-application-flow
      # @example
      #   Octokit.exchange_code_for_token('aaaa', 'xxxx', 'yyyy', {:accept => 'application/json'})
      def exchange_code_for_token(code, app_id = client_id, app_secret = client_secret, options = {})
        options = options.merge({
          :code => code,
          :client_id => app_id,
          :client_secret => app_secret,
          :headers => {
            :content_type => 'application/json',
            :accept       => 'application/json'
          }
        })

        post "#{web_endpoint}login/oauth/access_token", options
      end

      # Validate user username and password
      #
      # @param options [Hash] User credentials
      # @option options [String] :login GitHub login
      # @option options [String] :password GitHub password
      # @return [Boolean] True if credentials are valid
      def validate_credentials(options = {})
        !self.class.new(options).user.nil?
      rescue Octokit::Unauthorized
        false
      end

      # Update the authenticated user
      #
      # @param options [Hash] A customizable set of options.
      # @option options [String] :name
      # @option options [String] :email Publically visible email address.
      # @option options [String] :blog
      # @option options [String] :company
      # @option options [String] :location
      # @option options [Boolean] :hireable
      # @option options [String] :bio
      # @return [Sawyer::Resource]
      # @see https://developer.github.com/v3/users/#update-the-authenticated-user
      # @example
      #   Octokit.update_user(:name => "Erik Michaels-Ober", :email => "sferik@gmail.com", :company => "Code for America", :location => "San Francisco", :hireable => false)
      def update_user(options)
        patch "user", options
      end

      # Get a user's followers.
      #
      # @param user [Integer, String] GitHub user login or id of the user whose
      #   list of followers you are getting.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users
      #   followers.
      # @see https://developer.github.com/v3/users/followers/#list-followers-of-a-user
      # @example
      #   Octokit.followers('pengwynn')
      def followers(user=login, options = {})
        paginate "#{User.path user}/followers", options
      end

      # Get list of users a user is following.
      #
      # @param user [Intger, String] GitHub user login or id of the user who you
      #   are getting the list of the people they follow.
      # @return [Array<Sawyer::Resource>] Array of hashes representing users a
      #   user is following.
      # @see https://developer.github.com/v3/users/followers/#list-users-followed-by-another-user
      # @example
      #   Octokit.following('pengwynn')
      def following(user=login, options = {})
        paginate "#{User.path user}/following", options
      end

      # Check if you are following a user. Alternatively, check if a given user
      # is following a target user.
      #
      # Requries an authenticated client.
      #
      # @overload follows?(target)
      #   @param target [String] GitHub login of the user that you want to
      #   check if you are following.
      # @overload follows?(user, target)
      #   @param user [Integer, String] GitHub user login or id of first user
      #   @param target [String] GitHub login of the target user
      # @return [Boolean] True following target user, false otherwise.
      # @see https://developer.github.com/v3/users/followers/#check-if-you-are-following-a-user
      # @see https://developer.github.com/v3/users/followers/#check-if-one-user-follows-another
      # @example
      #   @client.follows?('pengwynn')
      # @example
      #   @client.follows?('catsby', 'pengwynn')
      def follows?(*args)
        target = args.pop
        user = args.first
        boolean_from_response :get, "#{User.path user}/following/#{target}"
      end

      # Follow a user.
      #
      # Requires authenticatied client.
      #
      # @param user [String] Username of the user to follow.
      # @return [Boolean] True if follow was successful, false otherwise.
      # @see https://developer.github.com/v3/users/followers/#follow-a-user
      # @example
      #   @client.follow('holman')
      def follow(user, options = {})
        boolean_from_response :put, "user/following/#{user}", options
      end

      # Unfollow a user.
      #
      # Requires authenticated client.
      #
      # @param user [String] Username of the user to unfollow.
      # @return [Boolean] True if unfollow was successful, false otherwise.
      # @see https://developer.github.com/v3/users/followers/#unfollow-a-user
      # @example
      #   @client.unfollow('holman')
      def unfollow(user, options = {})
        boolean_from_response :delete, "user/following/#{user}", options
      end

      # Get list of repos starred by a user.
      #
      # @param user [Integer, String] GitHub user login of the user to get the
      #   list of their starred repositories.
      # @param options [Hash] Optional options
      # @option options [String] :sort (created) Sort: <tt>created</tt> or <tt>updated</tt>.
      # @option options [String] :direction (desc) Direction: <tt>asc</tt> or <tt>desc</tt>.
      # @return [Array<Sawyer::Resource>] Array of hashes representing repositories starred by user.
      # @see https://developer.github.com/v3/activity/starring/#list-repositories-being-starred
      # @example
      #   Octokit.starred('pengwynn')
      def starred(user=login, options = {})
        paginate user_path(user, 'starred'), options
      end

      # Check if you are starring a repo.
      #
      # Requires authenticated client.
      #
      # @param repo [String, Hash, Repository] A GitHub repository
      # @return [Boolean] True if you are following the repo, false otherwise.
      # @see https://developer.github.com/v3/activity/starring/#check-if-you-are-starring-a-repository
      # @example
      #   @client.starred?('pengwynn/octokit')
      def starred?(repo, options = {})
        boolean_from_response :get, "user/starred/#{Repository.new(repo)}", options
      end

      # Get a public key.
      #
      # Note, when using dot notation to retrieve the values, ruby will return
      # the hash key for the public keys value instead of the actual value, use
      # symbol or key string to retrieve the value. See example.
      #
      # Requires authenticated client.
      #
      # @param key_id [Integer] Key to retreive.
      # @return [Sawyer::Resource] Hash representing the key.
      # @see https://developer.github.com/v3/users/keys/#get-a-single-public-key
      # @example
      #   @client.key(1)
      # @example Retrieve public key contents
      #   public_key = @client.key(1)
      #   public_key.key
      #   # => Error
      #
      #   public_key[:key]
      #   # => "ssh-rsa AAA..."
      #
      #   public_key['key']
      #   # => "ssh-rsa AAA..."
      def key(key_id, options = {})
        get "user/keys/#{key_id}", options
      end

      # Get list of public keys for user.
      #
      # Requires authenticated client.
      #
      # @return [Array<Sawyer::Resource>] Array of hashes representing public keys.
      # @see https://developer.github.com/v3/users/keys/#list-your-public-keys
      # @example
      #   @client.keys
      def keys(options = {})
        paginate "user/keys", options
      end

      # Get list of public keys for user.
      #
      # @param user [Integer, String] GitHub user login or id.
      # @return [Array<Sawyer::Resource>] Array of hashes representing public keys.
      # @see https://developer.github.com/v3/users/keys/#list-public-keys-for-a-user
      # @example
      #   @client.user_keys('pengwynn')
      def user_keys(user, options = {})
        # TODO: Roll this into .keys
        paginate "#{User.path user}/keys", options
      end

      # Add public key to user account.
      #
      # Requires authenticated client.
      #
      # @param title [String] Title to give reference to the public key.
      # @param key [String] Public key.
      # @return [Sawyer::Resource] Hash representing the newly added public key.
      # @see https://developer.github.com/v3/users/keys/#create-a-public-key
      # @example
      #   @client.add_key('Personal projects key', 'ssh-rsa AAA...')
      def add_key(title, key, options = {})
        post "user/keys", options.merge({:title => title, :key => key})
      end

      # Update a public key
      #
      # Requires authenticated client
      #
      # @param key_id [Integer] Id of key to update.
      # @param options [Hash] Hash containing attributes to update.
      # @option options [String] :title
      # @option options [String] :key
      # @return [Sawyer::Resource] Hash representing the updated public key.
      #
      # @deprecated This method is no longer supported in the API
      # @see https://developer.github.com/v3/users/keys/#update-a-public-key
      # @see https://developer.github.com/changes/2014-02-24-finer-grained-scopes-for-ssh-keys/
      # @example
      #   @client.update_key(1, :title => 'new title', :key => "ssh-rsa BBB")
      def update_key(key_id, options = {})
        patch "user/keys/#{key_id}", options
      end

      # Remove a public key from user account.
      #
      # Requires authenticated client.
      #
      # @param id [String] Id of the public key to remove.
      # @return [Boolean] True if removal was successful, false otherwise.
      # @see https://developer.github.com/v3/users/keys/#delete-a-public-key
      # @example
      #   @client.remove_key(1)
      def remove_key(id, options = {})
        boolean_from_response :delete, "user/keys/#{id}", options
      end

      # List email addresses for a user.
      #
      # Requires authenticated client.
      #
      # @return [Array<String>] Array of email addresses.
      # @see https://developer.github.com/v3/users/emails/#list-email-addresses-for-a-user
      # @example
      #   @client.emails
      def emails(options = {})
        paginate "user/emails", options
      end

      # Add email address to user.
      #
      # Requires authenticated client.
      #
      # @param email [String] Email address to add to the user.
      # @return [Array<String>] Array of all email addresses of the user.
      # @see https://developer.github.com/v3/users/emails/#add-email-addresses
      # @example
      #   @client.add_email('new_email@user.com')
      def add_email(email, options = {})
        email = Array(email)
        post "user/emails", email
      end

      # Remove email from user.
      #
      # Requires authenticated client.
      #
      # @param email [String] Email address to remove.
      # @return [Array<String>] Array of all email addresses of the user.
      # @see https://developer.github.com/v3/users/emails/#delete-email-addresses
      # @example
      #   @client.remove_email('old_email@user.com')
      def remove_email(email)
        email = Array(email)
        boolean_from_response :delete, "user/emails", email
      end

      # List repositories being watched by a user.
      #
      # @param user [Integer, String] GitHub user login or id.
      # @return [Array<Sawyer::Resource>] Array of repositories.
      # @see https://developer.github.com/v3/activity/watching/#list-repositories-being-watched
      # @example
      #   @client.subscriptions("pengwynn")
      def subscriptions(user=login, options = {})
        paginate user_path(user, 'subscriptions'), options
      end
      alias :watched :subscriptions

      # Initiates the generation of a migration archive.
      #
      # Requires authenticated user.
      #
      # @param repositories [Array<String>] :repositories Repositories for the organization.
      # @option options [Boolean, optional] :lock_repositories Indicates whether repositories should be locked during migration
      # @option options [Boolean, optional] :exclude_attachments Exclude attachments fro the migration data
      # @return [Sawyer::Resource] Hash representing the new migration.
      # @example
      #   @client.start_migration(['octocat/hello-world'])
      # @see https://docs.github.com/en/rest/reference/migrations#start-a-user-migration
      def start_user_migration(repositories, options = {})
        options = ensure_api_media_type(:migrations, options)
        options[:repositories] = repositories
        post "user/migrations", options
      end

      # Lists the most recent migrations.
      #
      # Requires authenticated user.
      #
      # @return [Array<Sawyer::Resource>] Array of migration resources.
      # @see https://docs.github.com/en/rest/reference/migrations#list-user-migrations
      def user_migrations(options = {})
        options = ensure_api_media_type(:migrations, options)
        paginate "user/migrations", options
      end

      # Fetches the status of a migration.
      #
      # Requires authenticated user.
      #
      # @param id [Integer] ID number of the migration.
      # @see https://docs.github.com/en/rest/reference/migrations#get-a-user-migration-status
      def user_migration_status(id, options = {})
        options = ensure_api_media_type(:migrations, options)
        get "user/migrations/#{id}", options
      end

      # Fetches the URL to a migration archive.
      #
      # Requires authenticated user.
      #
      # @param id [Integer] ID number of the migration.
      # @see https://docs.github.com/en/rest/reference/migrations#download-a-user-migration-archive
      def user_migration_archive_url(id, options = {})
        options = ensure_api_media_type(:migrations, options)
        url = "user/migrations/#{id}/archive"

        response = client_without_redirects(options).get(url)
        response.headers['location']
      end

      # Deletes a previous migration archive.
      #
      # Requires authenticated user.
      #
      # @param id [Integer] ID number of the migration.
      # @see https://docs.github.com/en/rest/reference/migrations#delete-a-user-migration-archive
      def delete_user_migration_archive(id, options = {})
        options = ensure_api_media_type(:migrations, options)
        delete "user/migrations/#{id}/archive", options
      end

      # List repositories for a user migration.
      #
      # Requires authenticated user.
      #
      # @param id [Integer] ID number of the migration.
      # @see https://docs.github.com/en/rest/reference/migrations#list-repositories-for-a-user-migration
      def user_migration_repositories(id, options = {})
        options = ensure_api_media_type(:migrations, options)
        get "user/migrations/#{id}/repositories", options
      end

      # Unlock a user repository which has been locked by a migration.
      #
      # Requires authenticated user.
      #
      # @param id [Integer] ID number of the migration.
      # @param repo [String] Name of the repository.
      # @see https://docs.github.com/en/rest/reference/migrations#unlock-a-user-repository
      def unlock_user_repository(id, repo, options = {})
        options = ensure_api_media_type(:migrations, options)
        delete "user/migrations/#{id}/repos/#{repo}/lock", options
      end
    end

    private
    # convenience method for constructing a user specific path, if the user is logged in
    def user_path(user, path)
      if user == login && user_authenticated?
        "user/#{path}"
      else
        "#{User.path user}/#{path}"
      end
    end
  end
end
