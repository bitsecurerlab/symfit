#ifndef PC_TRACKER_H
#define PC_TRACKER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <stdexcept>
#include "json.hpp"

using json = nlohmann::json;

// Structure to hold information about a tracked PC
struct TrackedPC {
    uint64_t pc;
    std::string loop_id;
    std::string loop_type;
    int source_line;
    uint64_t loop_body_start_pc;
    std::vector<std::string> relevant_variables;
    std::string why_relevant;
};

// Structure to hold the full Stage 1 analysis
struct Stage1Analysis {
    std::string vulnerability_summary;
    std::string vulnerable_function;
    std::vector<TrackedPC> loop_locations;
    uint64_t allocation_pc;
    uint64_t oob_write_pc;
};

class PCTracker {
private:
    Stage1Analysis analysis;
    std::unordered_map<uint64_t, std::ofstream*> constraint_logs;
    bool initialized;

    // Helper: Parse hex string to uint64_t
    static uint64_t parse_hex(const std::string& hex_str) {
        // Remove "0x" prefix if present
        std::string cleaned = hex_str;
        if (cleaned.substr(0, 2) == "0x" || cleaned.substr(0, 2) == "0X") {
            cleaned = cleaned.substr(2);
        }
        
        // Parse as hex
        return std::stoull(cleaned, nullptr, 16);
    }

public:
    PCTracker() : initialized(false) {}
    
    ~PCTracker() {
        // Close all log files
        for (auto& pair : constraint_logs) {
            if (pair.second) {
                pair.second->close();
                delete pair.second;
            }
        }
    }

    // Load the Stage 1 JSON configuration
    bool load_config(const std::string& json_path) {
        try {
            // Read JSON file
            std::ifstream config_file(json_path);
            if (!config_file.is_open()) {
                fprintf(stderr, "ERROR: Could not open config file: %s\n", json_path.c_str());
                return false;
            }

            // Parse JSON
            json config;
            config_file >> config;

            // Extract top-level fields
            analysis.vulnerability_summary = config["vulnerability_summary"].get<std::string>();
            analysis.vulnerable_function = config["vulnerable_function"].get<std::string>();
            
            // Parse allocation and OOB write PCs (optional fields)
            if (config.contains("allocation_pc") && !config["allocation_pc"].is_null()) {
                analysis.allocation_pc = parse_hex(config["allocation_pc"].get<std::string>());
            } else {
                analysis.allocation_pc = 0;
            }
            
            if (config.contains("oob_write_pc") && !config["oob_write_pc"].is_null()) {
                analysis.oob_write_pc = parse_hex(config["oob_write_pc"].get<std::string>());
            } else {
                analysis.oob_write_pc = 0;
            }

            // Parse loop locations
            for (const auto& loop_json : config["loop_locations"]) {
                TrackedPC tpc;
                
                // Required fields
                tpc.loop_id = loop_json["loop_id"].get<std::string>();
                tpc.loop_type = loop_json["loop_type"].get<std::string>();
                tpc.source_line = loop_json["source_line"].get<int>();
                tpc.why_relevant = loop_json["why_relevant"].get<std::string>();
                
                // Parse PC addresses
                tpc.pc = parse_hex(loop_json["loop_condition_pc"].get<std::string>());
                tpc.loop_body_start_pc = parse_hex(loop_json["loop_body_start_pc"].get<std::string>());
                
                // Parse relevant variables array
                for (const auto& var : loop_json["relevant_variables"]) {
                    tpc.relevant_variables.push_back(var.get<std::string>());
                }
                
                analysis.loop_locations.push_back(tpc);
            }

            fprintf(stderr, "✓ Loaded Stage 1 config: %s\n", json_path.c_str());
            fprintf(stderr, "  Function: %s\n", analysis.vulnerable_function.c_str());
            fprintf(stderr, "  Tracking %zu loop location(s)\n", analysis.loop_locations.size());
            
            initialized = true;
            return true;

        } catch (json::parse_error& e) {
            fprintf(stderr, "ERROR: JSON parse error: %s\n", e.what());
            fprintf(stderr, "       at byte %zu\n", e.byte);
            return false;
        } catch (json::type_error& e) {
            fprintf(stderr, "ERROR: JSON type error: %s\n", e.what());
            return false;
        } catch (std::exception& e) {
            fprintf(stderr, "ERROR: Failed to load config: %s\n", e.what());
            return false;
        }
    }

    // Initialize log files for tracked PCs
    bool init_log_files(const std::string& output_dir = "constraints") {
        if (!initialized) {
            fprintf(stderr, "ERROR: Cannot init log files - config not loaded\n");
            return false;
        }

        // Create output directory if it doesn't exist
        system(("mkdir -p " + output_dir).c_str());

        // Open log files for each tracked PC
        for (const auto& tpc : analysis.loop_locations) {
            char filename[512];
            snprintf(filename, sizeof(filename), 
                     "%s/pc_0x%llx_%s.log", 
                     output_dir.c_str(),
                     tpc.pc, 
                     tpc.loop_id.c_str());
            
            auto* log = new std::ofstream(filename, std::ios::out | std::ios::trunc);
            if (!log->is_open()) {
                fprintf(stderr, "ERROR: Could not open log file: %s\n", filename);
                delete log;
                continue;
            }

            // Write header
            *log << "=== Constraint Log for PC 0x" << std::hex << tpc.pc << " ===\n";
            *log << "Loop ID: " << tpc.loop_id << "\n";
            *log << "Loop Type: " << tpc.loop_type << "\n";
            *log << "Source Line: " << std::dec << tpc.source_line << "\n";
            *log << "Relevant Variables: ";
            for (size_t i = 0; i < tpc.relevant_variables.size(); i++) {
                *log << tpc.relevant_variables[i];
                if (i < tpc.relevant_variables.size() - 1) *log << ", ";
            }
            *log << "\n";
            *log << "Why Relevant: " << tpc.why_relevant << "\n";
            *log << "================================================\n\n";
            log->flush();

            constraint_logs[tpc.pc] = log;
            
            fprintf(stderr, "✓ Tracking PC 0x%llx (%s) -> %s\n", 
                    tpc.pc, tpc.loop_id.c_str(), filename);
        }

        // Also track allocation and OOB write PCs if present
        if (analysis.allocation_pc != 0) {
            char filename[512];
            snprintf(filename, sizeof(filename), 
                     "%s/pc_0x%llx_allocation.log", 
                     output_dir.c_str(),
                     analysis.allocation_pc);
            
            auto* log = new std::ofstream(filename, std::ios::out | std::ios::trunc);
            if (log->is_open()) {
                *log << "=== Allocation Site Constraints ===\n\n";
                log->flush();
                constraint_logs[analysis.allocation_pc] = log;
                fprintf(stderr, "✓ Tracking allocation PC 0x%llx\n", analysis.allocation_pc);
            }
        }

        if (analysis.oob_write_pc != 0) {
            char filename[512];
            snprintf(filename, sizeof(filename), 
                     "%s/pc_0x%llx_oob_write.log", 
                     output_dir.c_str(),
                     analysis.oob_write_pc);
            
            auto* log = new std::ofstream(filename, std::ios::out | std::ios::trunc);
            if (log->is_open()) {
                *log << "=== OOB Write Site Constraints ===\n\n";
                log->flush();
                constraint_logs[analysis.oob_write_pc] = log;
                fprintf(stderr, "✓ Tracking OOB write PC 0x%llx\n", analysis.oob_write_pc);
            }
        }

        return true;
    }

    // Check if a PC is being tracked
    bool is_tracked(uint64_t pc) const {
        return constraint_logs.find(pc) != constraint_logs.end();
    }

    // Get log file for a PC (returns nullptr if not tracked)
    std::ofstream* get_log(uint64_t pc) {
        auto it = constraint_logs.find(pc);
        return (it != constraint_logs.end()) ? it->second : nullptr;
    }

    // Get the analysis data
    const Stage1Analysis& get_analysis() const {
        return analysis;
    }

    bool is_initialized() const {
        return initialized;
    }
};

#endif // PC_TRACKER_H
