/**
 * Copyright 2020 the original author or authors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.bernardomg.util.ksgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bernardomg.util.ksgen.menu.KeystoreMenu;

import picocli.CommandLine;

/**
 * Main executable class.
 * 
 * @author Bernardo Martínez Garrido
 *
 */
public class Main {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    public static void main(final String[] args) {
        final Integer exitCode;

        exitCode = new CommandLine(new KeystoreMenu()).execute(args);

        LOGGER.debug("Exited with code {}", exitCode);

        System.exit(exitCode);
    }

    public Main() {
        super();
    }

}
