/**
 * Alfresco Content Services REST API
 * **Search API**  Provides access to the search features of Alfresco Content Services.
 *
 * OpenAPI spec version: 1
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 *
 * Swagger Codegen version: 2.3.1
 *
 * Do not edit the class manually.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['../../../alfrescoApiClient', '../model/GenericBucket'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../../../alfrescoApiClient'), require('./GenericBucket'));
  } else {
    // Browser globals (root is window)
    if (!root.AlfrescoContentServicesRestApi) {
      root.AlfrescoContentServicesRestApi = {};
    }
    root.AlfrescoContentServicesRestApi.GenericFacetResponse = factory(root.AlfrescoContentServicesRestApi.ApiClient, root.AlfrescoContentServicesRestApi.GenericBucket);
  }
}(this, function(ApiClient, GenericBucket) {
  'use strict';




  /**
   * The GenericFacetResponse model module.
   * @module model/GenericFacetResponse
   * @version 0.1.0
   */

  /**
   * Constructs a new <code>GenericFacetResponse</code>.
   * @alias module:model/GenericFacetResponse
   * @class
   */
  var exports = function() {
    var _this = this;




  };

  /**
   * Constructs a <code>GenericFacetResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {any} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GenericFacetResponse} obj Optional instance to populate.
   * @return {module:model/GenericFacetResponse} The populated <code>GenericFacetResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('label')) {
        obj['label'] = ApiClient.convertToType(data['label'], 'String');
      }
      if (data.hasOwnProperty('buckets')) {
        obj['buckets'] = ApiClient.convertToType(data['buckets'], [GenericBucket]);
      }
    }
    return obj;
  }

  /**
   * The facet type, eg. interval, range, pivot, stats
   * @member {string} type
   */
  exports.prototype['type'] = undefined;
  /**
   * The field name or its explicit label, if provided on the request
   * @member {string} label
   */
  exports.prototype['label'] = undefined;
  /**
   * An array of buckets and values
   * @member {module:model/GenericBucket[]} buckets
   */
  exports.prototype['buckets'] = undefined;



  return exports;
}));

