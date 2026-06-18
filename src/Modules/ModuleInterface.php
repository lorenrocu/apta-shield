<?php

namespace AptaShield\Modules;

defined('ABSPATH') || exit;

/**
 * Interface ModuleInterface
 * Defines contract for Apta Shield modules.
 */
interface ModuleInterface {
    
    /**
     * Start/execute the module hooks.
     */
    public function run();
}
