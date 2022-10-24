package decomp2dbg;

import decomp2dbg.D2DGhidraServer;

import java.awt.Event;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.swing.KeyStroke;

import docking.action.DockingAction;
import docking.ActionContext;
import docking.action.*;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.Msg;
import resources.ResourceManager;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Syncronize symbols to a debugger",
	description = "Debugging"
)
public class D2DPlugin extends ProgramPlugin implements DomainObjectListener {
	private DockingAction configureD2DAction;
	private D2DGhidraServer server;
	public Map<Long, DecompileResults> decompileCache;
	public Map<Long, String> gVarCache;
	public Map<Long, FunctionSymbol> funcSymCache;
	
	public D2DPlugin(PluginTool tool) {
		super(tool, true, true);
		
		// Add a d2d button to 'Tools' in GUI menu
		configureD2DAction = this.createD2DMenuAction();
		tool.addAction(configureD2DAction);
		
		// cache
		decompileCache = new HashMap<>();
		gVarCache = new HashMap<>();
		funcSymCache = new HashMap<>();
	}
	
	@Override
	public void init() {
		super.init();
	}

	@Override
	public void dispose() {
		super.dispose();
	}
	
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}
	
	private DockingAction createD2DMenuAction() {
		D2DPlugin plugin = this;
		configureD2DAction = new DockingAction("BinSync", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.configureD2DServer();
			}
		};
		
		configureD2DAction.setEnabled(true);
		configureD2DAction.setMenuBarData(new MenuData(new String[] {"Tools", "Configure decomp2dbg..." }));
		configureD2DAction.setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke('D', Event.CTRL_MASK + Event.SHIFT_MASK)));
		configureD2DAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/binsync.png")));
		return configureD2DAction;
	}
	
	
	private void configureD2DServer() {
		Msg.info(this, "Configuring decomp2dbg...");
		
		//TODO: make this configurable
		this.server = new D2DGhidraServer("localhost", 3662, this);
		this.server.start_server();
	}
	
	/*
	 * Change Event Handler
	 */
	
	
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// also look at:
		// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java
		// for more usage on this stufs
		
		ArrayList<Integer> funcEvents = new ArrayList<>(Arrays.asList(
			ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.DOCR_FUNCTION_BODY_CHANGED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED
		));

		ArrayList<Integer> symDelEvents = new ArrayList<>(Arrays.asList(
			ChangeManager.DOCR_SYMBOL_REMOVED	
		));
		
		ArrayList<Integer> symChgEvents = new ArrayList<>(Arrays.asList(
			ChangeManager.DOCR_SYMBOL_ADDED,
			ChangeManager.DOCR_SYMBOL_RENAMED,
			ChangeManager.DOCR_SYMBOL_DATA_CHANGED
		));
		
		
		for (DomainObjectChangeRecord record : ev) {
			// only analyze changes to the current program 
			if( !(record instanceof ProgramChangeRecord) )
				continue;
			
			int chgType = record.getEventType();
			var pcr = (ProgramChangeRecord) record;
			var obj = pcr.getObject();
			var newVal = pcr.getNewValue();
			
			/*
			 * Function Updates
			 */
			if(funcEvents.contains(chgType)) {
				// use record.getSubEvent() when checking if a FUNCTION_CHANGED
				// since it will be triggered if the signature of the function changes
				var funcAddr = pcr.getStart().getOffset();
				this.decompileCache.put(funcAddr, null);
			}
			
			/*
			 * Symbol Removed (global variable)
			 */
			else if (symDelEvents.contains(chgType)) {
				continue;
			}
			
			/*
			 * Symbol Updated or Created
			 */
			else if (symChgEvents.contains(chgType)) {
				if (obj == null && newVal != null)
					obj = newVal;
				
				/*
				 * Stack Variable
				 */
				if (obj instanceof VariableSymbolDB) {
					continue;
				}
				/*
				 * GlobalVar & Label
				 */
				else if(obj instanceof CodeSymbol) {
					var sym = (CodeSymbol) obj;
					var newName = sym.getName();
					var addr = sym.getAddress().getOffset();
					this.gVarCache.put(addr, newName);
				}
				/*
				 * Function Name
				 */
				else if(obj instanceof FunctionSymbol) {
					var sym = (FunctionSymbol) obj;
					var newName = sym.getName();
					var addr = sym.getAddress().getOffset();
					this.funcSymCache.put(addr, sym);
				}
				else
					continue;
				
				this.decompileCache.clear();
			}
		}
	}
	
}
