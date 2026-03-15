export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string
          name: string
          slug: string
          plan: string
          gdpr_dpo_email: string | null
          data_region: string
          max_pipelines: number
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          slug: string
          plan?: string
          gdpr_dpo_email?: string | null
          data_region?: string
          max_pipelines?: number
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          slug?: string
          plan?: string
          gdpr_dpo_email?: string | null
          data_region?: string
          max_pipelines?: number
          created_at?: string
          updated_at?: string
        }
      }
      profiles: {
        Row: {
          id: string
          org_id: string
          full_name: string
          is_active: boolean
          last_login_at: string | null
          created_at: string
        }
        Insert: {
          id: string
          org_id: string
          full_name?: string
          is_active?: boolean
          last_login_at?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          full_name?: string
          is_active?: boolean
          last_login_at?: string | null
          created_at?: string
        }
      }
      user_roles: {
        Row: {
          id: string
          user_id: string
          org_id: string
          role: "admin" | "dpo" | "developer" | "viewer"
          created_at: string
        }
        Insert: {
          id?: string
          user_id: string
          org_id: string
          role?: "admin" | "dpo" | "developer" | "viewer"
          created_at?: string
        }
        Update: {
          id?: string
          user_id?: string
          org_id?: string
          role?: "admin" | "dpo" | "developer" | "viewer"
          created_at?: string
        }
      }
      pipelines: {
        Row: {
          id: string
          org_id: string
          name: string
          sector: string
          llm_provider: string
          llm_model: string
          llm_endpoint_url: string | null
          status: string
          policy_set_id: string | null
          total_requests: number
          total_pii_detected: number
          total_pii_masked: number
          total_leaked: number
          avg_latency_ms: number
          created_by: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          name: string
          sector?: string
          llm_provider?: string
          llm_model?: string
          llm_endpoint_url?: string | null
          status?: string
          policy_set_id?: string | null
          total_requests?: number
          total_pii_detected?: number
          total_pii_masked?: number
          total_leaked?: number
          avg_latency_ms?: number
          created_by?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          name?: string
          sector?: string
          llm_provider?: string
          llm_model?: string
          llm_endpoint_url?: string | null
          status?: string
          policy_set_id?: string | null
          total_requests?: number
          total_pii_detected?: number
          total_pii_masked?: number
          total_leaked?: number
          avg_latency_ms?: number
          created_by?: string | null
          created_at?: string
          updated_at?: string
        }
      }
      policy_rules: {
        Row: {
          id: string
          org_id: string
          entity_type: string
          category: string
          action: string
          is_enabled: boolean
          regulation_ref: string | null
          applies_to_providers: string[]
          priority: number
          custom_pattern: string | null
          updated_by: string | null
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          entity_type: string
          category?: string
          action?: string
          is_enabled?: boolean
          regulation_ref?: string | null
          applies_to_providers?: string[]
          priority?: number
          custom_pattern?: string | null
          updated_by?: string | null
          updated_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          entity_type?: string
          category?: string
          action?: string
          is_enabled?: boolean
          regulation_ref?: string | null
          applies_to_providers?: string[]
          priority?: number
          custom_pattern?: string | null
          updated_by?: string | null
          updated_at?: string
        }
      }
      audit_logs: {
        Row: {
          id: string
          org_id: string
          pipeline_id: string | null
          user_id: string | null
          event_type: string
          entity_type: string
          entity_category: string
          action_taken: string
          severity: string
          token_id: string | null
          prompt_hash: string | null
          pipeline_stage: string | null
          regulation_triggered: string | null
          processing_ms: number | null
          source: string
          metadata: Json
          ibs_status: string
          ibs_evidence_id: string | null
          ibs_certification_hash: string | null
          ibs_network: string | null
          ibs_certified_at: string | null
          created_at: string
        }
        Insert: {
          id?: string
          org_id: string
          pipeline_id?: string | null
          user_id?: string | null
          event_type: string
          entity_type?: string
          entity_category?: string
          action_taken?: string
          severity?: string
          token_id?: string | null
          prompt_hash?: string | null
          pipeline_stage?: string | null
          regulation_triggered?: string | null
          processing_ms?: number | null
          source?: string
          metadata?: Json
          ibs_status?: string
          ibs_evidence_id?: string | null
          ibs_certification_hash?: string | null
          ibs_network?: string | null
          ibs_certified_at?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          pipeline_id?: string | null
          user_id?: string | null
          event_type?: string
          entity_type?: string
          entity_category?: string
          action_taken?: string
          severity?: string
          token_id?: string | null
          prompt_hash?: string | null
          pipeline_stage?: string | null
          regulation_triggered?: string | null
          processing_ms?: number | null
          source?: string
          metadata?: Json
          ibs_status?: string
          ibs_evidence_id?: string | null
          ibs_certification_hash?: string | null
          ibs_network?: string | null
          ibs_certified_at?: string | null
          created_at?: string
        }
      }
      pii_detections: {
        Row: {
          id: string
          audit_log_id: string
          org_id: string
          entity_type: string
          original_length: number | null
          token_ref: string | null
          start_offset: number | null
          end_offset: number | null
          confidence_score: number | null
          detector_used: string | null
          created_at: string
        }
        Insert: {
          id?: string
          audit_log_id: string
          org_id: string
          entity_type: string
          original_length?: number | null
          token_ref?: string | null
          start_offset?: number | null
          end_offset?: number | null
          confidence_score?: number | null
          detector_used?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          audit_log_id?: string
          org_id?: string
          entity_type?: string
          original_length?: number | null
          token_ref?: string | null
          start_offset?: number | null
          end_offset?: number | null
          confidence_score?: number | null
          detector_used?: string | null
          created_at?: string
        }
      }
      tokens_vault: {
        Row: {
          id: string
          org_id: string
          pipeline_id: string | null
          entity_type: string
          token_value: string
          encrypted_original: string
          encryption_key_id: string
          is_reversible: boolean
          access_roles: string[]
          expires_at: string | null
          reversal_count: number
          last_reversed_by: string | null
          last_reversed_at: string | null
          created_at: string
        }
        Insert: {
          id?: string
          org_id: string
          pipeline_id?: string | null
          entity_type: string
          token_value: string
          encrypted_original: string
          encryption_key_id?: string
          is_reversible?: boolean
          access_roles?: string[]
          expires_at?: string | null
          reversal_count?: number
          last_reversed_by?: string | null
          last_reversed_at?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          pipeline_id?: string | null
          entity_type?: string
          token_value?: string
          encrypted_original?: string
          encryption_key_id?: string
          is_reversible?: boolean
          access_roles?: string[]
          expires_at?: string | null
          reversal_count?: number
          last_reversed_by?: string | null
          last_reversed_at?: string | null
          created_at?: string
        }
      }
      api_keys: {
        Row: {
          id: string
          org_id: string
          name: string
          key_hash: string
          key_prefix: string
          pipeline_ids: string[] | null
          permissions: string[]
          is_active: boolean
          last_used_at: string | null
          expires_at: string | null
          created_by: string | null
          created_at: string
        }
        Insert: {
          id?: string
          org_id: string
          name: string
          key_hash: string
          key_prefix: string
          pipeline_ids?: string[] | null
          permissions?: string[]
          is_active?: boolean
          last_used_at?: string | null
          expires_at?: string | null
          created_by?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          name?: string
          key_hash?: string
          key_prefix?: string
          pipeline_ids?: string[] | null
          permissions?: string[]
          is_active?: boolean
          last_used_at?: string | null
          expires_at?: string | null
          created_by?: string | null
          created_at?: string
        }
      }
      ibs_sync_queue: {
        Row: {
          id: string
          audit_log_id: string
          org_id: string
          ibs_request_sent_at: string
          retry_count: number
          max_retries: number
          last_retry_at: string | null
          ibs_payload_hash: string
          status: string
          error_detail: string | null
          created_at: string
        }
        Insert: {
          id?: string
          audit_log_id: string
          org_id: string
          ibs_request_sent_at?: string
          retry_count?: number
          max_retries?: number
          last_retry_at?: string | null
          ibs_payload_hash?: string
          status?: string
          error_detail?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          audit_log_id?: string
          org_id?: string
          ibs_request_sent_at?: string
          retry_count?: number
          max_retries?: number
          last_retry_at?: string | null
          ibs_payload_hash?: string
          status?: string
          error_detail?: string | null
          created_at?: string
        }
      }
      llm_providers: {
        Row: {
          id: string
          org_id: string
          provider: string
          display_name: string
          is_active: boolean
          api_key_encrypted: string | null
          api_key_hint: string | null
          base_url: string | null
          available_models: string[]
          data_region: string
          gdpr_compliant: boolean
          created_by: string | null
          updated_by: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          provider: string
          display_name: string
          is_active?: boolean
          api_key_encrypted?: string | null
          api_key_hint?: string | null
          base_url?: string | null
          available_models?: string[]
          data_region?: string
          gdpr_compliant?: boolean
          created_by?: string | null
          updated_by?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          provider?: string
          display_name?: string
          is_active?: boolean
          api_key_encrypted?: string | null
          api_key_hint?: string | null
          base_url?: string | null
          available_models?: string[]
          data_region?: string
          gdpr_compliant?: boolean
          created_by?: string | null
          updated_by?: string | null
          created_at?: string
          updated_at?: string
        }
      }
      org_settings: {
        Row: {
          id: string
          org_id: string
          requests_limit: number
          requests_used: number
          billing_cycle_start: string
          enforce_gdpr_providers: boolean
          require_2fa_for_dpo: boolean
          session_timeout_min: number
          sandbox_enabled: boolean
          sandbox_log_events: boolean
          audit_retention_days: number
          token_ttl_days: number
          updated_by: string | null
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          requests_limit?: number
          requests_used?: number
          billing_cycle_start?: string
          enforce_gdpr_providers?: boolean
          require_2fa_for_dpo?: boolean
          session_timeout_min?: number
          sandbox_enabled?: boolean
          sandbox_log_events?: boolean
          audit_retention_days?: number
          token_ttl_days?: number
          updated_by?: string | null
          updated_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          requests_limit?: number
          requests_used?: number
          billing_cycle_start?: string
          enforce_gdpr_providers?: boolean
          require_2fa_for_dpo?: boolean
          session_timeout_min?: number
          sandbox_enabled?: boolean
          sandbox_log_events?: boolean
          audit_retention_days?: number
          token_ttl_days?: number
          updated_by?: string | null
          updated_at?: string
        }
      }
      org_notifications: {
        Row: {
          id: string
          org_id: string
          type: string
          is_enabled: boolean
          threshold: number | null
          recipients: string[]
          channel: string
          webhook_url: string | null
          last_triggered: string | null
          created_at: string
        }
        Insert: {
          id?: string
          org_id: string
          type: string
          is_enabled?: boolean
          threshold?: number | null
          recipients?: string[]
          channel?: string
          webhook_url?: string | null
          last_triggered?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          type?: string
          is_enabled?: boolean
          threshold?: number | null
          recipients?: string[]
          channel?: string
          webhook_url?: string | null
          last_triggered?: string | null
          created_at?: string
        }
      }
      conversations: {
        Row: {
          id: string
          org_id: string
          user_id: string
          pipeline_id: string
          title: string
          total_messages: number
          total_pii_detected: number
          total_pii_protected: number
          is_archived: boolean
          last_message_at: string | null
          created_at: string
        }
        Insert: {
          id?: string
          org_id: string
          user_id: string
          pipeline_id: string
          title?: string
          total_messages?: number
          total_pii_detected?: number
          total_pii_protected?: number
          is_archived?: boolean
          last_message_at?: string | null
          created_at?: string
        }
        Update: {
          id?: string
          org_id?: string
          user_id?: string
          pipeline_id?: string
          title?: string
          total_messages?: number
          total_pii_detected?: number
          total_pii_protected?: number
          is_archived?: boolean
          last_message_at?: string | null
          created_at?: string
        }
      }
      conversation_messages: {
        Row: {
          id: string
          conversation_id: string
          org_id: string
          user_id: string
          role: "user" | "assistant"
          content_protected: string
          content_preview: string | null
          audit_log_id: string | null
          pii_detected: number
          pii_protected: number
          processing_ms: number | null
          model_used: string | null
          tokens_used: number | null
          created_at: string
        }
        Insert: {
          id?: string
          conversation_id: string
          org_id: string
          user_id: string
          role: "user" | "assistant"
          content_protected: string
          content_preview?: string | null
          audit_log_id?: string | null
          pii_detected?: number
          pii_protected?: number
          processing_ms?: number | null
          model_used?: string | null
          tokens_used?: number | null
          created_at?: string
        }
        Update: {
          id?: string
          conversation_id?: string
          org_id?: string
          user_id?: string
          role?: "user" | "assistant"
          content_protected?: string
          content_preview?: string | null
          audit_log_id?: string | null
          pii_detected?: number
          pii_protected?: number
          processing_ms?: number | null
          model_used?: string | null
          tokens_used?: number | null
          created_at?: string
        }
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      get_user_org_id: {
        Args: { user_id: string }
        Returns: string
      }
      has_role: {
        Args: { user_id: string; check_role: string }
        Returns: boolean
      }
      has_any_role: {
        Args: { user_id: string; roles: string[] }
        Returns: boolean
      }
      increment_pipeline_stats: {
        Args: {
          p_pipeline_id: string
          p_requests?: number
          p_detected?: number
          p_masked?: number
          p_leaked?: number
          p_latency_ms?: number
        }
        Returns: undefined
      }
    }
    Enums: {
      app_role: "admin" | "dpo" | "developer" | "viewer"
    }
  }
}

export type Tables<T extends keyof Database["public"]["Tables"]> =
  Database["public"]["Tables"][T]["Row"]
export type Insertable<T extends keyof Database["public"]["Tables"]> =
  Database["public"]["Tables"][T]["Insert"]
export type Updateable<T extends keyof Database["public"]["Tables"]> =
  Database["public"]["Tables"][T]["Update"]
export type Enums<T extends keyof Database["public"]["Enums"]> =
  Database["public"]["Enums"][T]
