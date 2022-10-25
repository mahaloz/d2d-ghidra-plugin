package decomp2dbg;

import javax.swing.Icon;

import ghidra.framework.plugintool.util.PluginPackage;

/**
 * The {@link PluginPackage} for the {@value #NAME}
 */
public class D2DPluginPackage extends PluginPackage {
	public static final String NAME = "decomp2dbg decompiler server";
	private static final String DESCRIPTION = "These plugins are for connecting a debugger to the decompiler syms";
	
	protected D2DPluginPackage(String name, Icon icon, String description) {
		super(NAME, icon, DESCRIPTION);
	}
}
