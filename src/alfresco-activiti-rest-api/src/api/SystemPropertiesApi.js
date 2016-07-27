(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/SystemPropertiesRepresentation'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('../model/SystemPropertiesRepresentation'));
  } else {
    // Browser globals (root is window)
    if (!root.ActivitiPublicRestApi) {
      root.ActivitiPublicRestApi = {};
    }
    root.ActivitiPublicRestApi.SystemPropertiesApi = factory(root.ActivitiPublicRestApi.ApiClient, root.ActivitiPublicRestApi.SystemPropertiesRepresentation);
  }
}(this, function(ApiClient, SystemPropertiesRepresentation) {
  'use strict';

  /**
   * SystemProperties service.
   * @module api/SystemPropertiesApi
   * @version 1.4.0
   */

  /**
   * Constructs a new SystemPropertiesApi.
   * @alias module:api/SystemPropertiesApi
   * @class
   * @param {module:ApiClient} apiClient Optional API client implementation to use,
   * default to {@link module:ApiClient#instance} if unspecified.
   */
  var exports = function(apiClient) {
    this.apiClient = apiClient || ApiClient.instance;


    /**
     * Callback function to receive the result of the getProperties operation.
     * @callback module:api/SystemPropertiesApi~getPropertiesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/SystemPropertiesRepresentation} data The data returned by the service call.
     * @param {String} response The complete HTTP response.
     */

    /**
     * Retrieve System Properties
     * Typical value is AllowInvolveByEmail
     */
    this.getProperties = function() {
      var postBody = null;


      var pathParams = {
      };
      var queryParams = {
      };
      var headerParams = {
      };
      var formParams = {
      };

      var authNames = [];
      var contentTypes = ['application/json'];
      var accepts = ['application/json'];
      var returnType = SystemPropertiesRepresentation;

      return this.apiClient.callApi(
        '/api/enterprise/system/properties', 'GET',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }
  };

  return exports;
}));
