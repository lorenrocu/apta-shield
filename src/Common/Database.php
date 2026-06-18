<?php

namespace AptaShield\Common;

defined('ABSPATH') || exit;

/**
 * Class Database
 * Handles custom database tables and migration operations.
 */
class Database {
    
    /**
     * Get the name of the logs table.
     *
     * @return string
     */
    public static function get_logs_table() {
        global $wpdb;
        return $wpdb->prefix . 'apta_shield_logs';
    }

    /**
     * Get the name of the bans table.
     *
     * @return string
     */
    public static function get_bans_table() {
        global $wpdb;
        return $wpdb->prefix . 'apta_shield_bans';
    }

    /**
     * Get the name of the audit log table.
     *
     * @return string
     */
    public static function get_audit_table() {
        global $wpdb;
        return $wpdb->prefix . 'apta_shield_audit';
    }

    /**
     * Create custom tables on plugin activation.
     */
    public static function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $logs_table = self::get_logs_table();
        $bans_table = self::get_bans_table();
        $audit_table = self::get_audit_table();

        // Include upgrade file for dbDelta
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        // Logs table SQL
        $sql_logs = "CREATE TABLE $logs_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            ip_address varchar(45) NOT NULL,
            username varchar(100) DEFAULT NULL,
            details text DEFAULT NULL,
            created_at datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY ip_address (ip_address)
        ) $charset_collate;";

        // Bans table SQL
        $sql_bans = "CREATE TABLE $bans_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL UNIQUE,
            reason varchar(100) DEFAULT NULL,
            banned_until datetime NOT NULL,
            created_at datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY ip_address (ip_address),
            KEY banned_until (banned_until)
        ) $charset_collate;";

        // Audit log table SQL
        $sql_audit = "CREATE TABLE $audit_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            username varchar(100) DEFAULT NULL,
            action_type varchar(100) NOT NULL,
            ip_address varchar(45) NOT NULL,
            details text DEFAULT NULL,
            created_at datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY action_type (action_type),
            KEY user_id (user_id),
            KEY created_at (created_at)
        ) $charset_collate;";

        dbDelta($sql_logs);
        dbDelta($sql_bans);
        dbDelta($sql_audit);
    }

    /**
     * Drop custom tables on plugin uninstall (optional or on demand).
     */
    public static function drop_tables() {
        global $wpdb;
        $logs_table = self::get_logs_table();
        $bans_table = self::get_bans_table();
        $audit_table = self::get_audit_table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS $logs_table");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS $bans_table");
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
        $wpdb->query("DROP TABLE IF EXISTS $audit_table");
    }
}
