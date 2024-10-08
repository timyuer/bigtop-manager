/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.bigtop.manager.stack.bigtop.utils;

import org.apache.bigtop.manager.stack.core.exception.StackException;
import org.apache.bigtop.manager.stack.core.utils.LocalSettings;

import org.apache.commons.collections.CollectionUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.security.UserGroupInformation;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.net.URI;
import java.security.PrivilegedAction;
import java.text.MessageFormat;
import java.util.List;

@Data
@Slf4j
public class HdfsUtil {

    /**
     * Create directory on hdfs if not exist
     *
     * @param user      the system user to create the directory, which will infect the directory permission
     * @param directory the directory path on hdfs
     */
    public static void createDirectory(String user, String directory) {
        UserGroupInformation ugi = UserGroupInformation.createRemoteUser(user);
        try {
            ugi.doAs((PrivilegedAction<Void>) () -> {
                try (FileSystem fs = getFileSystem()) {
                    // Create dest dir if not exist
                    Path destDirPath = new Path(directory);
                    if (!fs.exists(destDirPath)) {
                        log.info("Creating directory [{}] on hdfs", destDirPath);
                        fs.mkdirs(destDirPath);
                    }
                } catch (Exception e) {
                    log.error("Error while creating directory on hdfs", e);
                    throw new StackException(e);
                }

                return null;
            });
        } catch (Exception e) {
            log.error("Error while creating directory on hdfs", e);
            throw new StackException(e);
        }
    }

    /**
     * Upload file to hdfs, this will keep original filename on hdfs
     *
     * @param user          the system user to upload the file, which will infect the file permission
     * @param localFilePath the local file path
     * @param destDir       the destination directory on hdfs
     */
    public static void uploadFile(String user, String localFilePath, String destDir) {
        uploadFile(user, localFilePath, destDir, null);
    }

    /**
     * Upload file to hdfs
     *
     * @param user          the system user to upload the file, which will infect the file permission
     * @param localFilePath the local file path
     * @param destDir       the destination directory on hdfs
     * @param destFilename  the destination filename on hdfs, if null, use the original filename
     */
    public static void uploadFile(String user, String localFilePath, String destDir, String destFilename) {
        UserGroupInformation ugi = UserGroupInformation.createRemoteUser(user);
        try {
            ugi.doAs((PrivilegedAction<Void>) () -> {
                try (FileSystem fs = getFileSystem()) {
                    // Create dest dir if not exist
                    Path destDirPath = new Path(destDir);
                    if (!fs.exists(destDirPath)) {
                        log.info("Creating directory [{}] on hdfs", destDirPath);
                        fs.mkdirs(destDirPath);
                    }

                    // upload file
                    String filename = destFilename == null
                            ? localFilePath.substring(localFilePath.lastIndexOf(File.separator) + 1)
                            : destFilename;
                    Path destFilePath = new Path(destDir, filename);
                    if (!fs.exists(destFilePath)) {
                        log.info("Uploading [{}] to hdfs [{}]", localFilePath, destFilePath);
                        fs.copyFromLocalFile(new Path(localFilePath), destFilePath);
                    }
                } catch (Exception e) {
                    log.error("Error while uploading file to hdfs", e);
                    throw new StackException(e);
                }

                return null;
            });
        } catch (Exception e) {
            log.error("Error while uploading file to hdfs", e);
            throw new StackException(e);
        }
    }

    /**
     * Get the hdfs FileSystem instance
     *
     * @return the hdfs FileSystem instance
     * @throws Exception if any error occurs
     */
    private static FileSystem getFileSystem() throws Exception {
        Configuration conf = new Configuration();
        conf.addResource(new Path("/etc/hadoop/conf/core-site.xml"));
        conf.addResource(new Path("/etc/hadoop/conf/hdfs-site.xml"));

        List<String> namenodeList = LocalSettings.hosts("namenode");
        if (CollectionUtils.isEmpty(namenodeList)) {
            String msg = "No namenode found in the cluster";
            log.error(msg);
            throw new StackException(msg);
        }

        String hdfsUri = MessageFormat.format("hdfs://{0}:8020", namenodeList.get(0));
        return FileSystem.get(new URI(hdfsUri), conf);
    }
}
