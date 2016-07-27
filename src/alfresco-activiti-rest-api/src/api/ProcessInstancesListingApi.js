(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/ProcessInstanceFilterRequestRepresentation', 'model/ResultListDataRepresentation', 'model/ObjectNode'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('../model/ProcessInstanceFilterRequestRepresentation'), require('../model/ResultListDataRepresentation'), require('../model/ObjectNode'));
  } else {
    // Browser globals (root is window)
    if (!root.ActivitiPublicRestApi) {
      root.ActivitiPublicRestApi = {};
    }
    root.ActivitiPublicRestApi.ProcessInstancesListingApi = factory(root.ActivitiPublicRestApi.ApiClient, root.ActivitiPublicRestApi.ProcessInstanceFilterRequestRepresentation, root.ActivitiPublicRestApi.ResultListDataRepresentation, root.ActivitiPublicRestApi.ObjectNode);
  }
}(this, function(ApiClient, ProcessInstanceFilterRequestRepresentation, ResultListDataRepresentation, ObjectNode) {
  'use strict';

  /**
   * ProcessInstancesListing service.
   * @module api/ProcessInstancesListingApi
   * @version 1.4.0
   */

  /**
   * Constructs a new ProcessInstancesListingApi.
   * @alias module:api/ProcessInstancesListingApi
   * @class
   * @param {module:ApiClient} apiClient Optional API client implementation to use,
   * default to {@link module:ApiClient#instance} if unspecified.
   */
  var exports = function(apiClient) {
    this.apiClient = apiClient || ApiClient.instance;


    /**
     * Callback function to receive the result of the filterProcessInstances operation.
     * @callback module:api/ProcessInstancesListingApi~filterProcessInstancesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ResultListDataRepresentation} data The data returned by the service call.
     * @param {String} response The complete HTTP response.
     */

    /**
     * Filter a list of process instances
     * @param {module:model/ProcessInstanceFilterRequestRepresentation} filterRequest filterRequest
     * @param {module:api/ProcessInstancesListingApi~filterProcessInstancesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {module:model/ResultListDataRepresentation}
     */
    this.filterProcessInstances = function(filterRequest) {
      var postBody = filterRequest;

      // verify the required parameter 'filterRequest' is set
      if (filterRequest == undefined || filterRequest == null) {
        throw "Missing the required parameter 'filterRequest' when calling filterProcessInstances";
      }


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
      var returnType = ResultListDataRepresentation;

      return this.apiClient.callApi(
        '/api/enterprise/process-instances/filter', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }

    /**
     * Callback function to receive the result of the getProcessInstances operation.
     * @callback module:api/ProcessInstancesListingApi~getProcessInstancesCallback
     * @param {String} error Error message, if any.
     * @param {module:model/ResultListDataRepresentation} data The data returned by the service call.
     * @param {String} response The complete HTTP response.
     */

    /**
     * Retrieve a list of process instances
     * @param {module:model/ObjectNode} requestNode requestNode
     * @param {module:api/ProcessInstancesListingApi~getProcessInstancesCallback} callback The callback function, accepting three arguments: error, data, response
     * data is of type: {module:model/ResultListDataRepresentation}
     */
    this.getProcessInstances = function(requestNode) {
      var postBody = requestNode;

      // verify the required parameter 'requestNode' is set
      if (requestNode == undefined || requestNode == null) {
        throw "Missing the required parameter 'requestNode' when calling getProcessInstances";
      }


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
      var returnType = ResultListDataRepresentation;

      return this.apiClient.callApi(
        '/api/enterprise/process-instances/query', 'POST',
        pathParams, queryParams, headerParams, formParams, postBody,
        authNames, contentTypes, accepts, returnType
      );
    }
  };

  return exports;
}));
