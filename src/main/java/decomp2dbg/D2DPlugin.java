package decomp2dbg;

import decomp2dbg.D2DGhidraServer;

import java.awt.Event;
import javax.swing.KeyStroke;

import docking.action.DockingAction;
import docking.ActionContext;
import docking.action.*;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
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
	
	public D2DPlugin(PluginTool tool) {
		super(tool, true, true);
		
		// Add a d2d button to 'Tools' in GUI menu
		configureD2DAction = this.createD2DMenuAction();
		tool.addAction(configureD2DAction);
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
		int[] program_undo_redo_events = new int[] {
			DomainObject.DO_OBJECT_RESTORED, 
			ChangeManager.DOCR_CODE_REMOVED
		};
		
		int[] cmt_events = new int[] {
			ChangeManager.DOCR_PRE_COMMENT_CHANGED,
			ChangeManager.DOCR_POST_COMMENT_CHANGED,
			ChangeManager.DOCR_EOL_COMMENT_CHANGED,
			ChangeManager.DOCR_PLATE_COMMENT_CHANGED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED,
		};
		
		int[] func_events = new int[] {
			ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.DOCR_FUNCTION_BODY_CHANGED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED
		};
		
		
		System.out.println("Change detected");
		if (this.eventContains(ev, program_undo_redo_events))
		{
			// reload or undo event has happend
			return;
		}
		
		// check for and handle commend added, comment deleted, and comment changed events
		if (this.eventContains(ev, cmt_events))
		{
			this.handleCmtChanged(ev);
		}
		else if(this.eventContains(ev, func_events))
		{
			System.out.println("Function changed!");
		}
	}
	
	private Boolean eventContains(DomainObjectChangedEvent ev, int[] events) {
		for (int event: events) {
			if (ev.containsEvent(event)) {
				return true;
			}
		}
		return false; 
	}
	
	/*
	 * Comments
	 */
	
	private int getCommentType(int type) {
		if (type == ChangeManager.DOCR_PRE_COMMENT_CHANGED) {
			return CodeUnit.PRE_COMMENT;
		}
		if (type == ChangeManager.DOCR_POST_COMMENT_CHANGED) {
			return CodeUnit.POST_COMMENT;
		}
		if (type == ChangeManager.DOCR_EOL_COMMENT_CHANGED) {
			return CodeUnit.EOL_COMMENT;
		}
		if (type == ChangeManager.DOCR_PLATE_COMMENT_CHANGED) {
			return CodeUnit.PLATE_COMMENT;
		}
		if ((type == ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) {
			return CodeUnit.REPEATABLE_COMMENT;
		}
		return -1;
	}
	
	private void handleCmtChanged(DomainObjectChangedEvent ev)
	{
		for (DomainObjectChangeRecord record : ev) {
			System.out.println("Comment changed called!");
			
			int type = record.getEventType();
			int commentType = getCommentType(type);
			if (commentType == -1) {
				continue;
			}

			ProgramChangeRecord pRec = (ProgramChangeRecord) record;

			String oldComment = (String) pRec.getOldValue();
			String newComment = (String) pRec.getNewValue();
			Address commentAddress = pRec.getStart();

			// if old comment is null then the change is an add comment so add the comment to the table
			if (oldComment == null) {
				//todo
				assert true;
			}

			// if the new comment is null then the change is a delete comment so remove the comment from the table
			else if (newComment == null) {
				//todo
				assert true;
			}
			// otherwise, the comment is changed so repaint the table
			else {
				//todo
				assert true;
			}
		}
		
	}

	
}
