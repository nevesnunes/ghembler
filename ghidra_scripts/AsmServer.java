//Assembly server
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseErrorResult;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyCompletion;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class AsmServer extends GhidraScript {

	private HttpServer server;
	private Assembler assembler;
	private Disassembler disassembler;
	private FlatProgramAPI fpa;

	private static final String ASSEMBLER_COMPLETION_TYPE = "type";
	private static final String ASSEMBLER_COMPLETION_DATA = "data";

	private static final String DISASSEMBLER_ADDRESS = "address";
	private static final String DISASSEMBLER_TYPE = "type";
	private static final String DISASSEMBLER_DATA = "data";
	private static final String DISASSEMBLER_PREVIOUS_LENGTH = "previousLength";

	private static final String TYPE_DIRECTIVE_FILL = "fill";
	private static final String TYPE_DIRECTIVE_LABEL = "label";
	private static final String TYPE_DIRECTIVE_ORIGIN = "origin";
	private static final String TYPE_INSTRUCTION = "instruction";

	private static final String UNKNOWN_BYTES = "??";

	// Either assembled hex bytes or disassembled display text
	private record AssemblyLine(Address address, String type, String data, long previousLength) {
	}

	@Override
	protected void run() throws Exception {
		setupProgram();
		setupServer();

		// Keep script running while we handle requests
		while (true) {
			try {
				Thread.sleep(500);
				monitor.checkCancelled();
			} catch (CancelledException e) {
				println("Stopping server...");
				break;
			}
		}
	}

	private void setupProgram() {
		assembler = Assemblers.getAssembler(currentProgram);
		disassembler = Disassembler.getDisassembler(currentProgram, monitor, DisassemblerMessageListener.CONSOLE);
		fpa = new FlatProgramAPI(currentProgram, monitor);
	}

	private void setupServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress(18000), 0);

		AssemblerHandler assemblerHandler = new AssemblerHandler();
		server.createContext("/assemble", assemblerHandler);
		DisassemblerHandler disassemblerHandler = new DisassemblerHandler();
		server.createContext("/disassemble", disassemblerHandler);

		server.setExecutor(Executors.newCachedThreadPool());
		server.start();
		println("Listening at port 18000...");
	}

	private AssemblyLine parseAssemblyLine(JsonReader jsonReader) throws IOException {
		jsonReader.beginObject();

		try {
			long addressOffset = 0;
			String type = TYPE_INSTRUCTION;
			String display = "";
			long previousLength = 0;
			while (jsonReader.hasNext()) {
				String name = jsonReader.nextName();
				if (name.equals(DISASSEMBLER_ADDRESS)) {
					addressOffset = jsonReader.nextLong();
				} else if (name.equals(DISASSEMBLER_TYPE)) {
					type = jsonReader.nextString();
				} else if (name.equals(DISASSEMBLER_DATA)) {
					display = jsonReader.nextString();
				} else if (name.equals(DISASSEMBLER_PREVIOUS_LENGTH)) {
					previousLength = jsonReader.nextLong();
				} else {
					throw new RuntimeException(String.format("Unknown disassembly field with name='%s'", name));
				}
			}
			Address address = toAddr(addressOffset);
			return new AssemblyLine(address, type, display, previousLength);
		} finally {
			jsonReader.endObject();
		}
	}

	@Override
	public void cleanup(boolean success) {
		if (server != null) {
			server.stop(1);
			println("Stopped server.");
		}
	}

	class AssemblerHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange he) throws IOException {
			if (he.getRequestMethod().equals("OPTIONS")) {
				addCORS(he, true);
				he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
				he.close();
				return;
			}

			he.getRequestHeaders();
			InputStream is = he.getRequestBody();
			byte[] data = is.readAllBytes();
			// println(new String(data));

			List<AssemblyLine> lines = parseAssemblyLines(data);
			boolean isBatch = lines.size() > 0 && lines.get(0).previousLength() > 0;

			he.getResponseHeaders().put("Access-Control-Allow-Origin", Collections.singletonList("*"));
			he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			try (OutputStream os = he.getResponseBody()) {
				JsonWriter jsonWriter = new JsonWriter(new OutputStreamWriter(os));
				jsonWriter.beginArray();

				if (isBatch) {
					computeCompletionsInBatch(gson, jsonWriter, lines);
				} else {
					computeCompletionsInStream(gson, jsonWriter, lines);
				}

				jsonWriter.endArray();
				jsonWriter.close();
			} catch (Exception e) {
				printerr(e.getMessage());
				printerr(Arrays.stream(e.getStackTrace())
						.map(StackTraceElement::toString)
						.collect(Collectors.joining("\n\t")));

				throw new RuntimeException(e);
			} finally {
				he.close();
			}
		}
	}

	private List<AssemblyLine> parseAssemblyLines(byte[] data) {
		final List<AssemblyLine> lines = new ArrayList<>();
		try (final JsonReader jsonReader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(data)))) {
			jsonReader.beginArray();

			while (jsonReader.hasNext()) {
				AssemblyLine line = parseAssemblyLine(jsonReader);
				println(String.format("Got '%s' @ 0x%08x => '%s'",
						line.type(),
						line.address().getUnsignedOffset(),
						line.data()));
				lines.add(line);
			}

			jsonReader.endArray();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		return lines;
	}

	private void putSymbol(Address address, String name) throws InvalidInputException {
		println(String.format("putSymbol '%s' @ 0x%08x", name, address.getUnsignedOffset()));
		currentProgram.getSymbolTable().getSymbols(name).forEach(Symbol::delete);
		currentProgram.getSymbolTable()
				.createLabel(address, name, currentProgram.getGlobalNamespace(), SourceType.USER_DEFINED);
	}

	private void computeCompletionsInBatch(Gson gson, JsonWriter jsonWriter, List<AssemblyLine> lines)
			throws IOException {
		Address nextAddress = lines.get(0).address();
		for (AssemblyLine line : lines) {
			jsonWriter.beginArray();

			if (line.type().equals(TYPE_INSTRUCTION)) {
				AssemblyInstruction candidateInstruction = null;
				long lastDiff = 9999;
				for (final AssemblyCompletion co : computeCompletions(nextAddress, line.data())) {
					if (co instanceof AssemblyInstruction) {
						// Addresses sent in batch request are assumed to always be the base offset,
						// since the client doesn't know about previous instruction lengths, so
						// we need to compute the next instruction's address, picking one of the
						// possible encodings (which might not match what the user previously picked).
						long candidateDiff = Math.abs(co.getDisplay().length() - line.previousLength);
						println(String.format("%s: %s-%s=%s last=%s\n", co.getDisplay().replaceAll("\\s+", ""), co.getDisplay().length(), line.previousLength, candidateDiff, lastDiff));
						if (candidateDiff < lastDiff) {
							lastDiff = candidateDiff;
							candidateInstruction = (AssemblyInstruction) co;
						}
					} else if (co instanceof AssemblySuggestion) {
						// println("Skipping AssemblySuggestion in batch mode");
					} else if (co instanceof AssemblyError) {
						JsonObject json = new JsonObject();
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "assembly_error");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getDisplay());
						gson.toJson(json, jsonWriter);
					} else {
						printerr(String.format("Unknown AssemblyCompletion '%s'", co));
					}
				}

				if (candidateInstruction != null) {
					try {
						byte[] memBytes = HexFormat.of()
								.parseHex(candidateInstruction.getDisplay().replaceAll("\\s+", ""));
						nextAddress = toAddr(nextAddress.getUnsignedOffset() + memBytes.length);

						JsonObject json = new JsonObject();
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "bytes");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, candidateInstruction.getDisplay());
						gson.toJson(json, jsonWriter);
					} catch (Exception e) {
						printerr(e.getMessage());
						printerr(Arrays.stream(e.getStackTrace())
								.map(StackTraceElement::toString)
								.collect(Collectors.joining("\n\t")));

						JsonObject json = new JsonObject();
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, e.getMessage());
						gson.toJson(json, jsonWriter);
					}
				}
			} else if (line.type().equals(TYPE_DIRECTIVE_ORIGIN)) {
				Address baseAddress = line.address();
				Address originAddress = toAddr(line.data());
				if (originAddress == null) {
					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
					json.addProperty(ASSEMBLER_COMPLETION_DATA, String.format("Invalid origin '%s'", line.data()));
					gson.toJson(json, jsonWriter);
				} else {
					nextAddress = toAddr(baseAddress.getUnsignedOffset() + originAddress.getUnsignedOffset());

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "ok");
					gson.toJson(json, jsonWriter);
				}
			} else if (line.type().equals(TYPE_DIRECTIVE_FILL)) {
				try {
					String[] parts = line.data().split(",");
					long n = Long.parseLong(parts[0]);
					byte[] memBytes = HexFormat.of().parseHex(parts[1]);
					StringBuilder outputBytes = new StringBuilder();
					for (long i = 0; i < n; i++) {
						putAt(nextAddress, memBytes);
						nextAddress = toAddr(nextAddress.getUnsignedOffset() + memBytes.length);
						outputBytes.append(HexFormat.ofDelimiter(" ").formatHex(memBytes) + " ");
					}

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "bytes");
					json.addProperty(ASSEMBLER_COMPLETION_DATA, outputBytes.toString());
					gson.toJson(json, jsonWriter);
				} catch (Exception e) {
					printerr(e.getMessage());
					printerr(Arrays.stream(e.getStackTrace())
							.map(StackTraceElement::toString)
							.collect(Collectors.joining("\n\t")));

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
					json.addProperty(ASSEMBLER_COMPLETION_DATA, e.getMessage());
					gson.toJson(json, jsonWriter);
				}
			} else if (line.type().equals(TYPE_DIRECTIVE_LABEL)) {
				try {
					putSymbol(nextAddress, line.data());

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "ok");
					gson.toJson(json, jsonWriter);
				} catch (Exception e) {
					printerr(e.getMessage());
					printerr(Arrays.stream(e.getStackTrace())
							.map(StackTraceElement::toString)
							.collect(Collectors.joining("\n\t")));

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
					json.addProperty(ASSEMBLER_COMPLETION_DATA, e.getMessage());
					gson.toJson(json, jsonWriter);
				}
			} else {
				JsonObject json = new JsonObject();
				json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
				json.addProperty(ASSEMBLER_COMPLETION_DATA, String.format("Unknown type '%s'", line.type()));
				gson.toJson(json, jsonWriter);
			}

			jsonWriter.endArray();
		}
	}

	private void computeCompletionsInStream(Gson gson, JsonWriter jsonWriter, List<AssemblyLine> lines)
			throws IOException {
		for (AssemblyLine line : lines) {
			jsonWriter.beginArray();

			if (line.type().equals(TYPE_INSTRUCTION)) {
				for (final AssemblyCompletion co : computeCompletions(line.address(), line.data())) {
					JsonObject json = new JsonObject();
					if (co instanceof AssemblyInstruction) {
						// Add all seen instructions, since stream mode is used to show
						// suggestion during auto-complete.
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "bytes");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getDisplay());
					} else if (co instanceof AssemblySuggestion) {
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "suggestion");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getText());
					} else if (co instanceof AssemblyError) {
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "assembly_error");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getDisplay());
					} else {
						printerr(String.format("Unknown AssemblyCompletion '%s'", co));
					}
					gson.toJson(json, jsonWriter);
				}
			} else if (line.type().equals(TYPE_DIRECTIVE_ORIGIN)) {
				// Ignored since there's no instruction to update
				JsonObject json = new JsonObject();
				json.addProperty(ASSEMBLER_COMPLETION_TYPE, "ok");
				gson.toJson(json, jsonWriter);
			} else if (line.type().equals(TYPE_DIRECTIVE_LABEL)) {
				try {
					putSymbol(line.address(), line.data());

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "ok");
					gson.toJson(json, jsonWriter);
				} catch (Exception e) {
					printerr(e.getMessage());
					printerr(Arrays.stream(e.getStackTrace())
							.map(StackTraceElement::toString)
							.collect(Collectors.joining("\n\t")));

					JsonObject json = new JsonObject();
					json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
					json.addProperty(ASSEMBLER_COMPLETION_DATA, e.getMessage());
					gson.toJson(json, jsonWriter);
				}
			} else {
				JsonObject json = new JsonObject();
				json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
				json.addProperty(ASSEMBLER_COMPLETION_DATA, String.format("Unknown type '%s'", line.type()));
				gson.toJson(json, jsonWriter);
			}

			jsonWriter.endArray();
		}
	}

	class DisassemblerHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange he) throws IOException {
			if (he.getRequestMethod().equals("OPTIONS")) {
				addCORS(he, true);
				he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
				he.close();
				return;
			}

			he.getRequestHeaders();
			InputStream is = he.getRequestBody();
			byte[] data = is.readAllBytes();
			// println(new String(data));

			List<AssemblyLine> lines = parseAssemblyLines(data);
			boolean isBatch = lines.size() > 1;

			he.getResponseHeaders().put("Access-Control-Allow-Origin", Collections.singletonList("*"));
			he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			try (OutputStream os = he.getResponseBody()) {
				JsonWriter jsonWriter = new JsonWriter(new OutputStreamWriter(os));

				if (isBatch) {
					computeDisassemblyInBatch(gson, jsonWriter, lines);
				} else {
					computeDisassemblyInStream(gson, jsonWriter, lines);
				}

				jsonWriter.close();
			} catch (Exception e) {
				printerr(e.getMessage());
				printerr(Arrays.stream(e.getStackTrace())
						.map(StackTraceElement::toString)
						.collect(Collectors.joining("\n\t")));

				throw new RuntimeException(e);
			} finally {
				he.close();
			}
		}
	}

	private void computeDisassemblyInBatch(Gson gson, JsonWriter jsonWriter, List<AssemblyLine> lines)
			throws MemoryAccessException {
		JsonArray jsonArray = new JsonArray();

		Address nextAddress = lines.get(0).address();
		for (final AssemblyLine line : lines) {
			try {
				putAt(nextAddress, line.data());
			} catch (Exception e) {
				printerr(e.getMessage());
				printerr(Arrays.stream(e.getStackTrace())
						.map(StackTraceElement::toString)
						.collect(Collectors.joining("\n\t")));

				jsonArray.add(new JsonPrimitive(UNKNOWN_BYTES));

				continue;
			}

			disassembler.disassemble(nextAddress, new AddressSet(nextAddress), false);
			final Instruction ins = currentProgram.getListing().getInstructionAt(nextAddress);
			if (ins == null) {
				printerr(String.format("Null instruction @ 0x%08x", nextAddress.getUnsignedOffset()));
				jsonArray.add(new JsonPrimitive(UNKNOWN_BYTES));
			} else {
				nextAddress = toAddr(nextAddress.getUnsignedOffset() + ins.getBytes().length);

				jsonArray.add(new JsonPrimitive(ins.toString()));
			}
		}

		gson.toJson(jsonArray, jsonWriter);
	}

	private void computeDisassemblyInStream(Gson gson, JsonWriter jsonWriter, List<AssemblyLine> lines) {
		JsonArray jsonArray = new JsonArray();

		for (final AssemblyLine line : lines) {
			try {
				putAt(line.address(), line.data());
			} catch (Exception e) {
				printerr(e.getMessage());
				printerr(Arrays.stream(e.getStackTrace())
						.map(StackTraceElement::toString)
						.collect(Collectors.joining("\n\t")));

				jsonArray.add(new JsonPrimitive(UNKNOWN_BYTES));

				continue;
			}

			disassembler.disassemble(line.address(), new AddressSet(line.address()), false);
			final Instruction ins = currentProgram.getListing().getInstructionAt(line.address());
			if (ins == null) {
				printerr(String.format("Null instruction @ 0x%08x", line.address().getUnsignedOffset()));
				jsonArray.add(new JsonPrimitive(UNKNOWN_BYTES));
			} else {
				jsonArray.add(new JsonPrimitive(ins.toString()));
			}
		}

		gson.toJson(jsonArray, jsonWriter);
	}

	private void addCORS(HttpExchange exchange, boolean isOptions) {
		exchange.getResponseHeaders().put("Access-Control-Allow-Headers", List.of("Origin", "Content-Type"));
		exchange.getResponseHeaders().put("Access-Control-Allow-Methods", List.of("GET", "POST", "OPTIONS"));
		exchange.getResponseHeaders().put("Access-Control-Allow-Origin", List.of("*"));
		if (isOptions) {
			exchange.getResponseHeaders().put("Allow", List.of("GET", "POST", "OPTIONS"));
		}
	}

	private void putAt(Address address, String hexBytes) throws Exception {
		if (hexBytes.isBlank()) {
			throw new RuntimeException(String.format("Null bytes to put @ 0x%08x", address.getUnsignedOffset()));
		}
		println(String.format("Put @ 0x%08x = '%s'", address.getUnsignedOffset(), hexBytes));

		byte[] memBytes = HexFormat.of().parseHex(hexBytes.replaceAll("\\s+", ""));
		putAt(address, memBytes);
	}

	private void putAt(Address address, byte[] memBytes) throws Exception {
		normalizeBlocks();

		boolean isContained = false;
		for (MemoryBlock mb : currentProgram.getMemory().getBlocks()) {
			if (mb.contains(address)) {
				isContained = true;
				break;
			}
		}

		if (!isContained) {
			// Create a new 0x10000 sized memory block containing the given address
			long startOffset = address.getUnsignedOffset() & 0xffff0000L;
			MemoryBlock mb = fpa.createMemoryBlock(Long
					.toHexString(startOffset), fpa.toAddr(startOffset), null, 0x10000, false);
			currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
		} else {
			// Clear any previously disassembled instructions
			currentProgram.getListing()
					.clearCodeUnits(address, toAddr(address.getUnsignedOffset() + memBytes.length), false);
		}

		currentProgram.getMemory().setBytes(address, memBytes, 0, memBytes.length);
	}

	private void normalizeBlocks() throws Exception {
		// Fill any gaps in existing blocks to make 0x10000 sized chunks
		Map<Address, Address> memoryBlockAddresses = new TreeMap<>();
		for (MemoryBlock mb : currentProgram.getMemory().getBlocks()) {
			memoryBlockAddresses.put(mb.getStart(), mb.getEnd());
		}

		long prevStart = 0;
		long prevEnd = 0;
		for (Map.Entry<Address, Address> entry : memoryBlockAddresses.entrySet()) {
			if (prevEnd == 0) {
				prevStart = entry.getKey().getUnsignedOffset();
				prevEnd = entry.getValue().getUnsignedOffset();

				long candidateStart = prevStart & 0xfffff000L;
				if (candidateStart != 0) {
					MemoryBlock mb = fpa.createMemoryBlock(Long
							.toHexString(0), fpa.toAddr(0), null, prevStart, false);
					currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
				}

				continue;
			}

			long currStart = entry.getKey().getUnsignedOffset();
			long currEnd = entry.getValue().getUnsignedOffset();
			if (prevEnd + 1 < currStart) {
				MemoryBlock mb = fpa.createMemoryBlock(Long
						.toHexString(prevEnd + 1), fpa.toAddr(prevEnd + 1), null, currStart - (prevEnd + 1), false);
				currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
			}

			prevStart = currStart;
			prevEnd = currEnd;
		}

		long lastEnd = (prevEnd & 0xffff0000L) + 0xffffL;
		if (prevEnd != lastEnd) {
			MemoryBlock mb = fpa.createMemoryBlock(Long
					.toHexString(prevEnd + 1), fpa.toAddr(prevEnd + 1), null, lastEnd - prevEnd, false);
			currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
		}
	}

	private Collection<AssemblyCompletion> computeCompletions(Address at, String line) {
		final AssemblyPatternBlock ctx = Objects.requireNonNull(getContext(assembler, at));

		Set<AssemblyCompletion> result = new TreeSet<>();
		Collection<AssemblyParseResult> parses = assembler.parseLine(line);
		for (AssemblyParseResult parse : parses) {
			if (parse.isError()) {
				AssemblyParseErrorResult err = (AssemblyParseErrorResult) parse;
				String buffer = err.getBuffer();
				for (String s : err.getSuggestions()) {
					if (s.startsWith(buffer)) {
						result.add(new AssemblySuggestion(s.substring(buffer.length()),
								formatSuggestion(line, s, buffer)));
					}
				}
			} else {
				AssemblyResolutionResults sems = assembler.resolveTree(parse, at, ctx);
				for (AssemblyResolution ar : sems) {
					if (ar.isError()) {
						result.add(new AssemblyError("", ar.toString()));
						continue;
					}
					AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
					for (byte[] ins : rc.possibleInsVals(ctx)) {
						result.add(new AssemblyInstruction(line, Arrays.copyOf(ins, ins.length), 0));
					}
				}
			}
		}

		if (result.isEmpty()) {
			result.add(new AssemblyError("", String.format("Invalid instruction and/or prefix: '%s'", line)));
		}
		return result;
	}

	protected String formatSuggestion(String prefix, String suggestion, String bufferleft) {
		String extra = suggestion.substring(bufferleft.length());
		String before = prefix.substring(0, prefix.length() - bufferleft.length());
		return String.format("%s%s%s", before, bufferleft, extra);
	}

	protected AssemblyPatternBlock getContext(Assembler assembler, Address address) {
		return assembler.getContextAt(address).fillMask();
	}

	/**
	 * Represents the description of an error encountered during parsing or
	 * assembling
	 */
	static class AssemblyError extends AssemblyCompletion {
		public AssemblyError(String text, String desc) {
			super(text, desc, Colors.ERROR, 1);
		}
	}

	/**
	 * Represents a textual suggestion to complete or partially complete an assembly
	 * instruction
	 */
	static class AssemblySuggestion extends AssemblyCompletion {
		public AssemblySuggestion(String text, String display) {
			super(text, display, null, 1);
		}
	}

	/**
	 * Represents an encoding for a complete assembly instruction
	 */
	static class AssemblyInstruction extends AssemblyCompletion {
		private byte[] data;

		public AssemblyInstruction(String text, byte[] data, int preference) {
			super("", NumericUtilities.convertBytesToString(data, " "), Colors.FOREGROUND, -preference);
			this.data = data;
		}

		public byte[] getData() {
			return data;
		}

		@Override
		public int compareTo(AssemblyCompletion ac) {
			if (!(ac instanceof AssemblyInstruction)) {
				return super.compareTo(ac);
			}
			AssemblyInstruction that = (AssemblyInstruction) ac;
			if (this.data.length != that.data.length) {
				return this.data.length - that.data.length;
			}
			return super.compareTo(ac);
		}
	}
}
