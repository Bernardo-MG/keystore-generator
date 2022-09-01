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

package com.bernardomg.util.ksgen.menu;

import com.bernardomg.util.ksgen.command.KeyStoreGeneratorCommand;
import com.bernardomg.util.ksgen.command.SymmetricKeyStoreGeneratorCommand;
import com.bernardomg.util.ksgen.version.ManifestVersionProvider;

import picocli.CommandLine.Command;

/**
 * Key store generation menu.
 *
 * @author Bernardo Martínez Garrido
 *
 */
@Command(description = "Creates key stores",
        subcommands = { KeyStoreGeneratorCommand.class, SymmetricKeyStoreGeneratorCommand.class },
        mixinStandardHelpOptions = true, versionProvider = ManifestVersionProvider.class)
public class KeystoreMenu {

    /**
     * Default constructor.
     */
    public KeystoreMenu() {
        super();
    }

}
