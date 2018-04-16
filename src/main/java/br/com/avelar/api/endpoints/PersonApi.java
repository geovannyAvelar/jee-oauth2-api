package br.com.avelar.api.endpoints;

import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import br.com.avelar.backend.model.Person;
import br.com.avelar.backend.service.PersonService;

@Path("/person")
@Produces({ MediaType.APPLICATION_JSON })
@Consumes({ MediaType.APPLICATION_JSON })
public class PersonApi {

    @Inject
    private PersonService personService;
    
    @GET
    public List<Person> findAll() {
        return personService.findAll(); 
    }

}
