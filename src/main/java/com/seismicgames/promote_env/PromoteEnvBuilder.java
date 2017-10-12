package com.seismicgames.promote_env;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class PromoteEnvBuilder extends Builder implements SimpleBuildStep {
    // static variables
    private static final String DISPLAY_NAME = "Promote S3 Environment";

    private final String fromEnv;
    private final String toEnv;
    private final String s3Bucket;
    private final String region;
    private final String credentialsId;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public PromoteEnvBuilder(String fromEnv, String toEnv, String s3Bucket, String region, String credentialsId) {
        this.fromEnv = fromEnv;
        this.toEnv = toEnv;
        this.s3Bucket = s3Bucket;
        this.region = region;
        this.credentialsId = credentialsId;
    }

    public String getFromEnv() {
        return fromEnv;
    }

    public String getToEnv() {
        return toEnv;
    }

    public String getS3Bucket() {
        return s3Bucket;
    }

    public String getRegion() {
        return region;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    @Override
    public void perform(Run<?,?> build, FilePath workspace, Launcher launcher, TaskListener listener) {
        AmazonWebServicesCredentials credentials = CredentialsProvider.findCredentialById(
                credentialsId,
                AmazonWebServicesCredentials.class,
                build,
                Collections.<DomainRequirement>emptyList()
        );

        if(credentials == null) {
            throw new RuntimeException("Can't find valid credentials to use to continue");
        }

        String toEnvironment = "";
        String fromEnvironment = "";
        String bucket = "";
        String awsRegion = "";

        try {
            toEnvironment = TokenMacro.expandAll(build, workspace, listener, toEnv);
            fromEnvironment = TokenMacro.expandAll(build, workspace, listener, fromEnv);
            bucket = TokenMacro.expandAll(build, workspace, listener, s3Bucket);
            awsRegion = TokenMacro.expandAll(build, workspace, listener, region);
        } catch (MacroEvaluationException | InterruptedException | IOException e) {
            listener.getLogger().println("Exception: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        if(RegionUtils.getRegion(awsRegion) == null) {
            listener.getLogger().println("Need to pass in a valid AWS Region");
            return;
        }

        final AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(credentials)
                .withRegion(awsRegion)
                .build();

        try {
            ObjectListing ol = s3.listObjects(bucket, fromEnvironment.toLowerCase());
            List<S3ObjectSummary> summaries = ol.getObjectSummaries();

            List<String> keys = new ArrayList<>();
            for (S3ObjectSummary summary : summaries) {
                if (summary.getKey().endsWith("latest")) {
                    keys.add(summary.getKey());
                }
            }

            S3Object o;
            List<String> keyParts;
            String version;
            String oldKey;
            String newKey;
            String newVersionKey;
            for (String key : keys) {
                o = s3.getObject(bucket, key);
                version = new BufferedReader(
                        new InputStreamReader(o.getObjectContent())).lines().collect(Collectors.joining(" ")).trim();
                keyParts = Arrays.asList(key.split("/"));
                oldKey = String.format("%s/%s/%s-%s.tar.gz", fromEnvironment, keyParts.get(1), keyParts.get(1), version);
                newKey = String.format("%s/%s/%s-%s.tar.gz", toEnvironment, keyParts.get(1), keyParts.get(1), version);
                listener.getLogger().println(String.format("Copying %s to %s", oldKey, newKey));
                s3.copyObject(bucket, oldKey, bucket, newKey);
                newVersionKey = String.format("%s/%s/latest", toEnvironment, keyParts.get(1));
                s3.copyObject(bucket, key, bucket, newVersionKey);
            }
        } catch (AmazonServiceException e) {
            listener.getLogger().println(e.getMessage());
        }
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * Descriptor for {@link PromoteEnvBuilder}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See {@code src/main/resources/hudson/plugins/hello_world/PromoteEnvBuilder/*.jelly}
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public DescriptorImpl() {
            load();
        }

        // Credentials select
        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String credentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();

            if(item == null) {
                if(!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if(!item.hasPermission(Item.EXTENDED_READ) && item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeMatchingAs(
                            item instanceof Queue.Task ? Tasks.getAuthenticationOf((Queue.Task)item) : ACL.SYSTEM,
                            item,
                            AmazonWebServicesCredentials.class,
                            Collections.<DomainRequirement>emptyList(),
                            CredentialsMatchers.instanceOf(AmazonWebServicesCredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        public FormValidation doCheckFromEnv(@QueryParameter String value)
                throws IOException, ServletException {
            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please set a 'from' environment");
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckToEnv(@QueryParameter String value)
                throws IOException, ServletException {
            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please set a 'to' environment");
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckS3Bucket(@QueryParameter String value)
                throws IOException, ServletException {
            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please set an AWS S3 bucket to work in");
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckRegion(@QueryParameter String value)
                throws IOException, ServletException {
            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please set an AWS region to use");
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckCredentialsId(@AncestorInPath Item item, @QueryParameter String value) {
            if (item == null) {
                if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                    return FormValidation.ok();
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return FormValidation.ok();
                }
            }

            if (StringUtils.isEmpty(value)) {
                return FormValidation.error("Please select valid credentials");
            }

            if (value.startsWith("${") && value.endsWith("}")) {
                return FormValidation.error("Cannot use expression based credentials");
            }

            for (ListBoxModel.Option o : CredentialsProvider.listCredentials(
                    AmazonWebServicesCredentials.class,
                    item,
                    item instanceof Queue.Task ? Tasks.getAuthenticationOf((Queue.Task)item) : ACL.SYSTEM,
                    Collections.<DomainRequirement>emptyList(),
                    CredentialsMatchers.instanceOf(AmazonWebServicesCredentials.class)
            )) {
                if(StringUtils.equals(value, o.value)) {
                    return FormValidation.ok();
                }
            }

            return FormValidation.ok();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return DISPLAY_NAME;
        }
    }
}

