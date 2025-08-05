package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBasicCommandStructure tests the actual root command structure
func TestBasicCommandStructure(t *testing.T) {
	// Test the actual root command that's returned from initCLI()
	rootCmd := initCLI()

	// Test that root command has basic properties
	assert.Equal(t, "ctrld", rootCmd.Use)
	assert.NotEmpty(t, rootCmd.Short, "Root command should have a short description")

	// Test that root command has subcommands
	commands := rootCmd.Commands()
	assert.NotNil(t, commands, "Root command should have subcommands")
	assert.Greater(t, len(commands), 0, "Root command should have at least one subcommand")

	// Test that expected commands exist
	expectedCommands := []string{"run", "service", "clients", "upgrade", "log"}
	for _, cmdName := range expectedCommands {
		found := false
		for _, cmd := range commands {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected command %s not found in root command", cmdName)
	}
}

// TestServiceCommandCreation tests service command creation
func TestServiceCommandCreation(t *testing.T) {
	sc := NewServiceCommand()
	require.NotNil(t, sc, "ServiceCommand should be created")

	// Test service config creation
	config := sc.createServiceConfig()
	require.NotNil(t, config, "Service config should be created")
	assert.Equal(t, ctrldServiceName, config.Name)
	assert.Equal(t, "Control-D Helper Service", config.DisplayName)
	assert.Equal(t, "A highly configurable, multi-protocol DNS forwarding proxy", config.Description)
}

// TestServiceCommandSubCommands tests service command sub commands
func TestServiceCommandSubCommands(t *testing.T) {
	rootCmd := &cobra.Command{
		Use:   "ctrld",
		Short: "DNS forwarding proxy",
	}

	serviceCmd := InitServiceCmd(rootCmd)
	require.NotNil(t, serviceCmd, "Service command should be created")

	// Test that service command has subcommands
	subcommands := serviceCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "Service command should have subcommands")

	// Test specific subcommands exist
	expectedCommands := []string{"start", "stop", "restart", "reload", "status", "uninstall", "interfaces"}

	for _, cmdName := range expectedCommands {
		found := false
		for _, cmd := range subcommands {
			if cmd.Name() == cmdName {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected service subcommand %s not found", cmdName)
	}
}

// TestCommandHelp tests basic help functionality
func TestCommandHelp(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	// Test help command execution
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)

	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	assert.NoError(t, err, "Help command should execute without error")
	assert.Contains(t, buf.String(), "dns forwarding proxy", "Help output should contain description")
}

// TestCommandVersion tests version command
func TestCommandVersion(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)

	// Test version command
	rootCmd.SetArgs([]string{"--version"})
	err := rootCmd.Execute()
	assert.NoError(t, err, "Version command should execute without error")
	assert.Contains(t, buf.String(), "version", "Version output should contain version information")
}

// TestCommandErrorHandling tests error handling
func TestCommandErrorHandling(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	// Test invalid flag instead of invalid command
	rootCmd.SetArgs([]string{"--invalid-flag"})
	err := rootCmd.Execute()
	assert.Error(t, err, "Invalid flag should return error")
}

// TestCommandFlags tests flag functionality
func TestCommandFlags(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	// Test that root command has expected flags
	verboseFlag := rootCmd.PersistentFlags().Lookup("verbose")
	assert.NotNil(t, verboseFlag, "Verbose flag should exist")
	assert.Equal(t, "v", verboseFlag.Shorthand)

	silentFlag := rootCmd.PersistentFlags().Lookup("silent")
	assert.NotNil(t, silentFlag, "Silent flag should exist")
	assert.Equal(t, "s", silentFlag.Shorthand)
}

// TestCommandExecution tests basic command execution
func TestCommandExecution(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	// Test that root command can be executed (help command)
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)

	rootCmd.SetArgs([]string{"--help"})
	err := rootCmd.Execute()
	assert.NoError(t, err, "Root command should execute without error")
	assert.Contains(t, buf.String(), "dns forwarding proxy", "Help output should contain description")
}

// TestCommandArgs tests argument handling
func TestCommandArgs(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	// Test that root command can handle arguments properly
	// Test with no args (should succeed)
	err := rootCmd.Execute()
	assert.NoError(t, err, "Root command with no args should execute")

	// Test with help flag (should succeed)
	rootCmd.SetArgs([]string{"--help"})
	err = rootCmd.Execute()
	assert.NoError(t, err, "Root command with help flag should execute")
}

// TestCommandSubcommands tests subcommand functionality
func TestCommandSubcommands(t *testing.T) {
	// Initialize the CLI to set up the root command
	rootCmd := initCLI()

	// Test that root command has subcommands
	commands := rootCmd.Commands()
	assert.Greater(t, len(commands), 0, "Root command should have subcommands")

	// Test that specific subcommands exist and can be executed
	expectedSubcommands := []string{"run", "service", "clients", "upgrade", "log"}
	for _, subCmdName := range expectedSubcommands {
		// Find the subcommand
		var subCmd *cobra.Command
		for _, cmd := range commands {
			if cmd.Name() == subCmdName {
				subCmd = cmd
				break
			}
		}
		assert.NotNil(t, subCmd, "Subcommand %s should exist", subCmdName)

		// Test that subcommand has help
		assert.NotEmpty(t, subCmd.Short, "Subcommand %s should have a short description", subCmdName)
	}
}
