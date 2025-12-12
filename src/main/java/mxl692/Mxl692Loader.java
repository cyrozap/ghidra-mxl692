// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2025 Forest Crossman <cyrozap@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mxl692;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A loader for MxL692 firmware images.
 */
public class Mxl692Loader extends AbstractProgramWrapperLoader {

	private static final byte[] FW_HEADER = new byte[]{(byte)0x4d, (byte)0x31, (byte)0x10, (byte)0x02, (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x80};
	private static final long CODE_START = 0x40000000L;

	private record MemoryRegion(String name, long baseAddress, long size) {}

	private static final List<MemoryRegion> MMIO_REGIONS = List.of(
		new MemoryRegion("MMIO_7_0", 0x70000000, 0x10000),
		new MemoryRegion("MMIO_8_0", 0x80000000, 0x10000),
		new MemoryRegion("MMIO_8_1_INTR", 0x80010000, 0x10000),
		new MemoryRegion("MMIO_9_0_TUNER", 0x90000000, 0x10000),
		new MemoryRegion("MMIO_9_1_TUNER", 0x90010000, 0x10000),
		new MemoryRegion("MMIO_9_2_QAM_DEMOD", 0x90020000, 0x10000),
		new MemoryRegion("MMIO_9_3_ATSC_DEMOD", 0x90030000, 0x10000),
		new MemoryRegion("MMIO_9_4_IO_CFG", 0x90040000, 0x10000),
		new MemoryRegion("MMIO_9_5_QAM_OOB_DEMOD", 0x90050000, 0x10000)
	);

	private static long bigEndianToLong(byte[] bytes) {
		long value = 0;
		for (int i = 0; i < bytes.length; i++) {
			value <<= 8;
			value |= (bytes[i] & 0xFFL);
		}
		return value;
	}

	@Override
	public String getName() {
		return "MxL692 Firmware";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Check header
		byte[] headerBytes = provider.readBytes(0, 8);
		if (Arrays.equals(headerBytes, FW_HEADER)) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("Xtensa:BE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		Memory mem = program.getMemory();
		FlatProgramAPI api = new FlatProgramAPI(program);
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		// Read and validate header
		byte[] headerBytes = provider.readBytes(0, 8);
		if (!Arrays.equals(headerBytes, FW_HEADER)) {
			throw new IOException("Invalid header magic bytes");
		}

		// Read body length (24-bit big-endian)
		long bodyLen = bigEndianToLong(provider.readBytes(8, 3));

		// Read checksum
		byte checksum = provider.readByte(11);

		// Validate length
		long actualLength = provider.length() - 16;
		if (actualLength != bodyLen) {
			throw new IOException("Invalid firmware length. Expected " + actualLength + ", got " + bodyLen + ".");
		}

		// Validate checksum
		byte[] data = provider.readBytes(16, bodyLen);
		byte calculatedChecksum = 0;
		for (byte b : data) {
			calculatedChecksum += b;
		}
		if (calculatedChecksum != checksum) {
			throw new IOException("Invalid checksum");
		}

		// Parse body segments
		long dataCount = 0;
		long textCount = 0;
		long offset = 16;
		while (offset < provider.length()) {
			// Read segment magic byte
			byte magic = provider.readByte(offset++);
			if (magic != 0x53) {
				throw new IOException("Invalid segment magic byte at offset " + offset);
			}

			// Read segment length (24-bit big-endian)
			long len = bigEndianToLong(provider.readBytes(offset, 3));
			offset += 3;

			// Read segment address (32-bit big-endian)
			long addr = bigEndianToLong(provider.readBytes(offset, 4));
			offset += 4;

			// Create memory block for this segment
			MemoryBlock block;
			try {
				String name;
				if (addr >= CODE_START) {
					name = ".text." + (textCount++);
				} else {
					name = ".data." + (dataCount++);
				}
				block = mem.createInitializedBlock(name, api.toAddr(addr), fileBytes, offset, len, false);
			} catch (AddressOverflowException | LockException | MemoryConflictException e) {
				throw new IOException(e);
			}
			if (addr >= CODE_START) {
				block.setPermissions(true, false, true);
			} else {
				block.setPermissions(true, true, false);
			}
			block.setVolatile(false);
			offset += len;

			// Skip padding to align to 4-byte boundary
			int misalignment = (int) (offset & 3);
			if (misalignment != 0) {
				offset += 4 - misalignment;
			}
		}

		// Create MMIO regions
		for (MemoryRegion region : MMIO_REGIONS) {
			MemoryBlock block;
			try {
				block = mem.createUninitializedBlock(region.name(), api.toAddr("0x" + Long.toHexString(region.baseAddress())), region.size(), false);
			} catch (AddressOverflowException | LockException | MemoryConflictException e) {
				throw new IOException(e);
			}
			block.setPermissions(true, true, false);
			block.setVolatile(true);
		}
	}

	@Override
	public boolean shouldApplyProcessorLabelsByDefault() {
		return true;
	}
}
