## Work with dev-containers in vs code

### 1. Add .devcontainer to root directory, and add there file devcontainer.json
```
// For format details, see https://aka.ms/devcontainer.json. For config options, see the
// README at: https://github.com/devcontainers/templates/tree/main/src/java
{
	"name": "Java",
	// Or use a Dockerfile or Docker Compose file. More info: https://containers.dev/guide/dockerfile
	"image": "mcr.microsoft.com/devcontainers/java:1-21-bullseye",

	"features": {
		"ghcr.io/devcontainers/features/java:1": {
			"version": "none",
			"installMaven": "true",
			"installGradle": "false"
		}
	}

	// Use 'forwardPorts' to make a list of ports inside the container available locally.
	// "forwardPorts": [],

	// Use 'postCreateCommand' to run commands after the container is created.
	// "postCreateCommand": "java -version",

	// Configure tool-specific properties.
	// "customizations": {},

	// Uncomment to connect as root instead. More info: https://aka.ms/dev-containers-non-root.
	// "remoteUser": "root"
}
```

### 2. Run via command palette (ctrl + p) as Dev Containers: Reopen in container

### 3. Create java proejct

```
mvn archetype:generate -DgroupId=src.main.java \
    -DartifactId=bai-lab-id \
    -DarchetypeArtifactId=maven-archetype-quickstart \
    -DinteractiveMode=false
```

### 4. Compile and run
```
mvn compile exec:java -Dexec.mainClass="package_in_src_main_java.Main"
```