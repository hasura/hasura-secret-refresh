A template string contains substrings of the form ##secret##. Any substring of 
the form ##secret## will be replaced by the actual secret when the template is processed.

eg. If the template is "Bearer ##secret##"" and the provided secret is "123", the final
result would be "Bearer 123".

Templates also support simple JSON secrets.

eg. If the secret is '{"token": 123}' and the template is "Bearer ##secret.token##",
then the final string will be "Bearer 123"

Note that only simple JSON objects are supported. All keys of the JSON object
must be a string and all values must be either number/string/boolean. That is,
the JSON object must be a map from string -> number/boolean/string.

Nested JSON objects, arrays etc. will not work as expected.
