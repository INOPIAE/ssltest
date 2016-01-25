package de.dogcraft.ssltest.dns.encoding;


public class EntityContainer<E extends Entity> {

    private Class<E> ce;

    private E entity;

    public EntityContainer(Class<E> ce) {
        this.ce = ce;
        try {
            this.entity = ce.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            this.entity = null;
        }
    }

    public EntityContainer(E e) {
        this.ce = (Class<E>) e.getClass();
        this.entity = e;
    }

    public E getEntity() {
        return entity;
    }

    public void setEntity(E entity) {
        this.entity = entity;
    }

}
