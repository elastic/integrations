# Developer workflow: release a bug fix for supporting older package version?

In some cases, when we drop the support for an older version of the stack and later on find
out needing to add a bug fix to the some old package version, we have to make some manual changes
to release the bug fix to users. For example: in this [PR](https://github.com/elastic/integrations/pull/3688)
(AWS package version 1.23.4), it was dropped support
for Kibana version 7.x and bumped the AWS package version from 1.19.5 to 1.20.0. But we found
a bug in the EC2 dashboard that needs to be fixed with Kibana version 7.x. So instead of
adding a new AWS package version 1.23.5, we need to fix it between 1.19.5 and 1.20.0.

Here there wil be detailed the steps to follow to release a fix for a given package version:

1. **Find git commit (package version) that needs to be fixed**

   In the example above, the commit to be fixed is the one right before this
   [PR](https://github.com/elastic/integrations/pull/3688) updating package `aws`:
    - Using the web:
        - Look for the merge commit of the PR
            - https://github.com/elastic/integrations/commit/aa63e1f6a61d2a017e1f88af2735db129cc68e0c
            - It can be found as one of the last messages in the PR
              ![merged commit](./images/merge_commit_message.png)
        - And then show the previous commits for that changeset inside the package folder (e.g. `packages/aws`):
            - https://github.com/elastic/integrations/commits/aa63e1f6a61d2a017e1f88af2735db129cc68e0c/packages/aws/
              ![commits from package](./images/browse_package_commits.png)
    - Using the command line:

      ```bash
      cd packages/<package_name>
      git log --grep "#<pr_id>" .
      git log -n 1 <merge_commit>^ .

      # following the example
      $ cd packages/aws
      $ git log --grep "#3688"
      commit aa63e1f6a61d2a017e1f88af2735db129cc68e0c
      Author: Joe Reuter <email@johannes-reuter.de>
      Date:   Mon Aug 8 17:14:55 2022 +0200
      
          Inline all aws dashboards (#3688)
          
          * inline all aws dashboards
          
          * format
          
          * apply the right format
          
          * inline again
          
          * format
      $ git log -n 1 aa63e1f6a61d2a017e1f88af2735db129cc68e0c^ .
      commit 8cb321075afb9b77ea965e1373a03a603d9c9796
      Author: Mario Castro <mariocaster@gmail.com>
      Date:   Thu Aug 4 16:52:06 2022 +0200
      
          Move lightweight manifest to integration for EBS data stream (#3856)
      ```

2. **Create a branch**

   Create a branch out of the commit from the previous step (8cb321075afb9b77ea965e1373a03a603d9c9796) and name it following this pattern: `backport-<package_name>-<package_major_version>.<package_minor_version>`.
   For example: `backport-aws-1.19`.

3. **Create a PR for the bug fix**

   Apply bugfixes and open a PR against the `backport-<package_name>-<package_major_version>.<package_minor_version>` branch created above.


Once this PR is merged, this new version of the package is going to be published automatically following the usual CI/CD jobs.
