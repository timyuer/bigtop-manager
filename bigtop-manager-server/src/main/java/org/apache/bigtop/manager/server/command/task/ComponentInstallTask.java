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
package org.apache.bigtop.manager.server.command.task;

import org.apache.bigtop.manager.common.enums.Command;
import org.apache.bigtop.manager.common.enums.MaintainState;
import org.apache.bigtop.manager.dao.po.HostComponentPO;

public class ComponentInstallTask extends AbstractComponentTask {

    public ComponentInstallTask(TaskContext taskContext) {
        super(taskContext);
    }

    @Override
    protected Command getCommand() {
        return Command.INSTALL;
    }

    @Override
    public void onSuccess() {
        super.onSuccess();

        Long clusterId = taskContext.getClusterId();
        String componentName = taskContext.getComponentName();
        String hostname = taskContext.getHostname();
        HostComponentPO hostComponentPO =
                hostComponentMapper.findByClusterIdAndComponentNameAndHostname(clusterId, componentName, hostname);
        hostComponentPO.setState(MaintainState.INSTALLED.getName());
        hostComponentMapper.updateById(hostComponentPO);
    }

    @Override
    public String getName() {
        return "Install " + taskContext.getComponentDisplayName() + " on " + taskContext.getHostname();
    }
}
