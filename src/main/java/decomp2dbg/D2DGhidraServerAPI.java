package decomp2dbg;

import java.util.ArrayList;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.webserver.WebServer;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.flatapi.*;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.GoToService;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.database.function.LocalVariableDB;

import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.util.data.DataTypeParser; 
import ghidra.util.data.DataTypeParser.AllowedDataTypes; 
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.comments.SetCommentCmd;

import decomp2dbg.D2DGhidraServer;

public class D2DGhidraServerAPI {
    private D2DGhidraServer server;
	
	public D2DGhidraServerAPI(D2DGhidraServer server) {
		this.server = server;
	}
	
	/*
	 * Server Manipulation API 
	 */
	
	public Boolean ping() {
		return true;
	}
	
	public Boolean stop() {
		this.server.stop_server();
		return true;
	}
	
	/*
	 * Utils
	 */
	
	private Function getNearestFunction(Address addr) {
		if(addr == null) {
			Msg.warn(this, "Failed to parse Addr string earlier, got null addr.");
			return null;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var funcManager = program.getFunctionManager();
		var func =  funcManager.getFunctionContaining(addr);
		
		return func;
	}
	
	private Address rebaseAddr(Integer addr, Boolean rebaseDown) {
		var program = this.server.plugin.getCurrentProgram();
		var base = (int) program.getImageBase().getOffset();
		Integer rebasedAddr = addr;
		if(rebaseDown) {
			rebasedAddr -= base;
		}
		else if(addr < base) {
			rebasedAddr += base;
		}
		
		return this.strToAddr(Integer.toHexString(rebasedAddr));
	}
	
	private Address strToAddr(String addrStr) {
		return this.server.plugin.getCurrentProgram().getAddressFactory().getAddress(addrStr);
	}
	
	private DecompileResults decompileFunc(Function func) {
		var cacheRes = this.server.plugin.decompileCache.get(func.getEntryPoint().getOffset());
		if(cacheRes != null) {
			Msg.info(this, "Cache hit!");
			return (DecompileResults) cacheRes; 
		}
		
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.openProgram(this.server.plugin.getCurrentProgram());
		DecompileResults res = ifc.decompileFunction(func, 10, new ConsoleTaskMonitor());
		
		// cache it!
		this.server.plugin.decompileCache.put(func.getEntryPoint().getOffset(), res);
		return res;
	}
	
	private LocalVariableDB getStackVariable(Function func, int offset) {
		for (Variable v : func.getAllVariables()) {
			if(v.getStackOffset() == offset) {
				return (LocalVariableDB) v;
			}
		}
		
		return null;
	}
	
	private DataType parseTypeString(String typeStr)
	{
		var dtService = this.server.plugin.getTool().getService(DataTypeManagerService.class);
		//var anan = AutoAnalysisManager.getAnalysisManager(this.server.plugin.getCurrentProgram()).getDataTypeManagerService();
		var dtParser = new DataTypeParser(dtService, AllowedDataTypes.ALL);
		
		DataType parsedType;
		try {
			parsedType = dtParser.parse(typeStr);
		} catch (Exception ex) {
			parsedType = null;
		}
		
		return parsedType;
	}
	
	private FunctionDefinitionDataType parsePrototypeStr(String protoStr) 
	{
		// string must look something like:
		// 'void function1(int p1, int p2)' 
		var program = this.server.plugin.getCurrentProgram();
		var funcDefn = CParserUtils.parseSignature((ServiceProvider) null, program, protoStr);
		return funcDefn;
	}
	
	/*
	 * 
	 * Decompiler API
	 *
	 */
	
	public Map<String, Object> decompile(Integer addr) {
		// useful code: https://gist.github.com/guedou/a358df609c80d9fdc1ec4c348129005b
		Map<String, Object> resp = new HashMap<>();
		resp.put("decompilation", "");
		resp.put("curr_line", -1);
		resp.put("func_name", "");
		
		var rebasedAddr = this.rebaseAddr(addr, false);
		var func = this.getNearestFunction(this.rebaseAddr(addr, false));
		var rebasedAddrLong = rebasedAddr.getOffset();
		
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);
			return resp;
		}
		
		resp.put("func_name", func.getName());
		
		var dec = this.decompileFunc(func);
		if(dec == null) {
			Msg.warn(server, "Failed to decompile function by the address " + addr);
			return resp;
		}
	    
		// create a nice string
	    var decLines = dec.getDecompiledFunction().getC().split("\n");
	    resp.put("decompilation", decLines);
		
		PrettyPrinter pp = new PrettyPrinter(func, dec.getCCodeMarkup());
	    ArrayList<ClangLine> lines = pp.getLines();
	    
	    // locate the decompilation line
	    Boolean lineFound = false;
	    Integer lineNumber = 0;
	    for (ClangLine line : lines) {
	    	for (int i = 0; i < line.getNumTokens(); i++) {
				if (line.getToken(i).getMinAddress() == null) {
					continue; 
				}
				long tokenMinAddr = line.getToken(i).getMinAddress().getOffset();
				long tokenMaxAddr = line.getToken(i).getMaxAddress().getOffset();
				if(tokenMinAddr == rebasedAddrLong || tokenMaxAddr == rebasedAddrLong || 
						(rebasedAddrLong > tokenMinAddr && rebasedAddrLong < tokenMaxAddr)) {
					lineFound = true;
					lineNumber = line.getLineNumber();
					break;
				}
	    	}
	    	
	    	if(lineFound)
				break;
	    }
	    
	    // unable to locate the decompilation line
	    if(!lineFound)
	    	return resp;
	    
	    resp.put("curr_line", lineNumber-1);
		return resp;
	}
	
	
	public Map<String, Object> function_data(Integer addr) {
		Map<String, Object> resp = new HashMap<>();
		resp.put("stack_vars", new HashMap<>());
		resp.put("reg_vars", new HashMap<>());
		var func = this.getNearestFunction(this.rebaseAddr(addr, false));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);
			return resp;
		}
		
		var dec = this.decompileFunc(func);
		if(dec == null) {
			Msg.warn(server, "Failed to decompile function by the address " + addr);
			return resp;
		}
		
		ArrayList<HighSymbol> symbols = new ArrayList<HighSymbol>();
		Map<String, Object> regVars = new HashMap<>();
		Map<String, Object> stackVars = new HashMap<>();
		dec.getHighFunction().getLocalSymbolMap().getSymbols().forEachRemaining(symbols::add);
		for (HighSymbol sym: symbols) {
			if(sym.getStorage().isStackStorage()) {
				Map<String, String> sv = new HashMap<>();
				sv.put("name", sym.getName());
				sv.put("type", sym.getDataType().toString());
				stackVars.put(String.valueOf(sym.getStorage().getStackOffset()), sv);
			}
			else if(sym.getStorage().isRegisterStorage()) {
				Map<String, String> rv = new HashMap<>();
				rv.put("reg_name", sym.getStorage().getRegister().toString().toLowerCase());
				rv.put("type", sym.getDataType().toString());
				regVars.put(sym.getName(), rv);
			}
		}
		resp.put("stack_vars", stackVars);
		resp.put("reg_vars", regVars);
		
		return resp;
	}

	public Map<String, Object> function_headers() {
		Map<String, Object> resp = new HashMap<>();
		var program = this.server.plugin.getCurrentProgram();
		var fm = program.getFunctionManager();
		var functions = fm.getFunctions(true);
		for (Function func : functions) {
			Map<String, Object> funcInfo = new HashMap<>();
			funcInfo.put("name", func.getName());
			funcInfo.put("size", (int) func.getBody().getNumAddresses());
			var rebasedAddr = this.rebaseAddr((int) func.getEntryPoint().getOffset(), true);
			resp.put("0x" + rebasedAddr.toString(), funcInfo);
			
		}
		
		return resp;
	}
	
	public Map<String, Object> global_vars() {
		/*
		 * TODO:
		 * Read this to recap on the progress of global vars:
		 * - we have the dict for storing the cache, which we can get all symbols and their addrs
		 * - FOR BINSYNC:
		 * 	- we still need to get the type for each global var, as well as the size if possible
		 * 	- currently we can get a reference to the global_label, but that gets us something 'undefined8' and such 
		 * 	- need to find if we can convert those to the correct type 
		 * - FOR D2D:
		 * 	1. Check if a symbol change shows the name
		 *  2. Populate the cache on change 
		var dm = this.server.plugin.getCurrentProgram().getDataTypeManager();
		var lst = this.server.plugin.getCurrentProgram().getListing();
		var data = lst.getDataAt(this.rebaseAddr(0xdead, false));
		var dType = data.getDataType();
		 */
		// this code is for getting the type of a global variable ^^^
		
		Map<String, Object> resp = new HashMap<>();
		var symTab = this.server.plugin.getCurrentProgram().getSymbolTable();
		
		for (Symbol sym: symTab.getAllSymbols(false)) {
			if (sym.getSymbolType() != SymbolType.LABEL)
				continue;
			
			Map<String, Object> varInfo = new HashMap<>();
			varInfo.put("name", sym.getName());
			var rebasedAddr = this.rebaseAddr((int) sym.getAddress().getOffset(), true);
			resp.put("0x" + rebasedAddr.toString(), varInfo);
		}
		
		
		return resp;
	}
	
}
