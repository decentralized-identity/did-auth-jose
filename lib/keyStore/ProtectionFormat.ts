
 /**
  * Enum to define different protection formats
  */
export enum ProtectionFormat {
  /**
   * Format for a flat JSON signature
   */
  FlatJsonJws = 0,

  /**
   * Format for a compact JSON signature
   */
  CompactJsonJws,

  /**
   * Format for a compact JSON encryption
   */
  CompactJsonJwe,

  /**
   * Format for a flat JSON encryption
   */
  FlatJsonJwe
}
