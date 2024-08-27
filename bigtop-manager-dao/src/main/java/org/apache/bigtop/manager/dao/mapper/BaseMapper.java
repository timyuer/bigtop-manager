/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.bigtop.manager.dao.mapper;

import org.apache.bigtop.manager.dao.sql.BaseSqlProvider;

import org.apache.ibatis.annotations.DeleteProvider;
import org.apache.ibatis.annotations.InsertProvider;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.UpdateProvider;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface BaseMapper<Entity> {

    /**
     * Insert the entity.
     */
    @Options(useGeneratedKeys = true, keyProperty = "id", keyColumn = "id")
    @InsertProvider(type = BaseSqlProvider.class, method = "insert")
    int save(Entity entity);

    /**
     * Update the entity by primary key.
     */
    @UpdateProvider(type = BaseSqlProvider.class, method = "updateById")
    int updateById(Entity entity);

    /**
     * Query the entity by primary key.
     */
    @SelectProvider(type = BaseSqlProvider.class, method = "selectById")
    Entity findById(Serializable id);

    /**
     * Query the entity by primary key.
     */
    default Optional<Entity> findOptionalById(Serializable id) {
        return Optional.ofNullable(findById(id));
    }

    /**
     * Query the entity by primary key.
     */
    @SelectProvider(type = BaseSqlProvider.class, method = "selectByIds")
    List<Entity> findByIds(Collection<? extends Serializable> ids);

    /**
     * Query all entities.
     */
    @SelectProvider(type = BaseSqlProvider.class, method = "selectAll")
    List<Entity> findAll();

    @DeleteProvider(type = BaseSqlProvider.class, method = "deleteById")
    boolean deleteById(Serializable id);

    @DeleteProvider(type = BaseSqlProvider.class, method = "deleteByIds")
    boolean deleteByIds(Collection<? extends Serializable> ids);
}